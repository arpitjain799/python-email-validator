from typing import Optional

from .exceptions_types import EmailUndeliverableError, ValidatedEmail

import asyncio

import dns.resolver
import dns.asyncresolver
import dns.exception


def caching_resolver(*, timeout=None, cache=None, _async=False):
    if timeout is None:
        from . import DEFAULT_TIMEOUT
        timeout = DEFAULT_TIMEOUT
    if not _async:
        resolver = dns.resolver.get_default_resolver()
    else:
        resolver = dns.asyncresolver.get_default_resolver()
    resolver.cache = cache or dns.resolver.LRUCache()  # type: ignore
    resolver.lifetime = timeout  # type: ignore # timeout, in seconds
    return resolver


def validate_email_deliverability(emailinfo: ValidatedEmail, timeout: Optional[int] = None, dns_resolver=None, _async:bool = False):
    # Check that the domain resolves to an MX record. If there is no MX record,
    # try an A or AAAA record which is a deprecated fallback for deliverability.
    # Raises an EmailUndeliverableError on failure. On success, updates emailinfo.
    #
    # When _async is False, returns nothing. When _async is True, returns a Future.

    # In tests, emailinfo is passed as a domain name string.
    if isinstance(emailinfo, str):
        domain = emailinfo
        emailinfo = ValidatedEmail()
        emailinfo.domain = domain
        emailinfo.ascii_domain = domain

    # If no dns.resolver.Resolver was given, get dnspython's default resolver.
    # Override the default resolver's timeout. This may affect other uses of
    # dnspython in this process.
    if dns_resolver is None:
        from . import DEFAULT_TIMEOUT
        if timeout is None:
            timeout = DEFAULT_TIMEOUT
        if not _async:
            dns_resolver = dns.resolver.get_default_resolver()
        else:
            dns_resolver = dns.asyncresolver.get_default_resolver()
        dns_resolver.lifetime = timeout

    if _async:
        loop = asyncio.get_event_loop()
        future = loop.create_future()

    def dns_query(domain, record, callback):
        # When run synchronously or with a synchronous dns.resolver instance,
        # the query is executed and the callback function is called immediately
        # with the result or an exception instance.
        if not _async or not isinstance(dns_resolver, dns.asyncresolver.Resolver):
            if isinstance(dns_resolver, dns.asyncresolver.Resolver):
                callback(exception=Exception("Asynchronous dns_resolver cannot be used when called synchronously."))
            try:
                # We need a way to check how timeouts are handled in the tests. So we
                # have a secret variable that if set makes this method always test the
                # handling of a timeout.
                if getattr(validate_email_deliverability, 'TEST_CHECK_TIMEOUT', False):
                    raise dns.exception.Timeout()

                callback(response=dns_resolver.resolve(domain, record))
            except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                callback(exception=e)

        # When run asynchronously, a task is executed asynchronsouly that executes the DNS
        # query and passes the result or exception to the callback. The callback must eventually
        # call the done() function which finishes the Future for the call to validate_email_deliverability.
        else:
            async def do_query():
                try:
                    callback(response=await dns_resolver.resolve(domain, record))
                except (dns.resolver.NoNameservers, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                    callback(exception=e)
            asyncio.create_task(do_query())

    def done(exception=None):
        # Timeouts are a local problem, probably, so we don't reject
        # email addresses in that case.
        if exception is dns.exception.Timeout:
            if not _async:
                return
            else:
                future.set_result(emailinfo)

        if not _async:
            if exception:
                raise exception
        else:
            if exception:
                future.set_exception(exception)
            else:
                # The future returns the validated email object.
                future.set_result(emailinfo)

    def got_spf_result(response=None, exception=None):
        if response:
            # Check for a SPF reject all ("v=spf1 -all") record which indicates
            # no emails are sent from this domain, which like a NULL MX record
            # would indicate that the domain is not used for email.
            # Ignore exceptions.
            for rec in response:
                value = b"".join(rec.strings)
                if value.startswith(b"v=spf1 "):
                    emailinfo.spf = value.decode("ascii", errors='replace')
                    if value == b"v=spf1 -all":
                        done(exception=EmailUndeliverableError(f"The domain name {emailinfo.domain} does not send email."))
                        return
        done()

    def check_spf_record():
        dns_query(emailinfo.ascii_domain, "TXT", callback=got_spf_result)

    def got_aaaa_record(response=None, exception=None):
        if exception:
            # If there was no MX, A, or AAAA record, then mail to
            # this domain is not deliverable.
            return done(exception=EmailUndeliverableError(f"The domain name {emailinfo.domain} does not exist."))

        # We got an AAAA record.
        emailinfo.mx = [(0, str(r)) for r in response]
        emailinfo.mx_fallback_type = "AAAA"

        # Now check SPF.
        check_spf_record()

    def got_a_record(response=None, exception=None):
        if exception:
            # If there was no MX or A record, fall back to an AAAA record.
            dns_query(emailinfo.ascii_domain, "AAAA", callback=got_aaaa_record)
            return

        # We got an A record.
        emailinfo.mx = [(0, str(r)) for r in response]
        emailinfo.mx_fallback_type = "A"

        # Now check SPF.
        check_spf_record()

    def got_mx_record(response=None, exception=None):
        if exception:
            # If there was no MX record, fall back to an A record.
            dns_query(emailinfo.ascii_domain, "A", callback=got_a_record)
            return

        # We got one or more MX records.

        # For reporting, put them in priority order and remove the trailing dot in the qnames.
        mtas = sorted([(r.preference, str(r.exchange).rstrip('.')) for r in response])

        # Remove "null MX" records from the list (their value is (0, ".") but we've stripped
        # trailing dots, so the 'exchange' is just ""). If there was only a null MX record,
        # email is not deliverable.
        mtas = [(preference, exchange) for preference, exchange in mtas
                if exchange != ""]
        if len(mtas) == 0:
            done(exception=EmailUndeliverableError(f"The domain name {emailinfo.domain} does not accept email."))
            return

        emailinfo.mx = mtas
        emailinfo.mx_fallback_type = None

        # Now check SPF.
        check_spf_record()

    dns_query(emailinfo.ascii_domain, "MX", callback=got_mx_record)

    if _async:
        # Return the Future when calling asynchronously.
        return future
