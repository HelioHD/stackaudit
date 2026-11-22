# Security Policy

## Intended use

stackaudit is a reconnaissance and misconfiguration tool for systems **you are authorized
to test** — your own deployments or an engagement with explicit written scope.

- The **passive** default only requests what a browser already downloads.
- The **active** mode requires the explicit `--authorized` flag and is still deliberately
  limited: it reads Supabase row counts via `HEAD` + `Prefer: count=exact` and never
  downloads rows, never writes, and never validates a discovered secret against its provider.

Running the active mode against a system you do not own or have permission to test may be
illegal in your jurisdiction (in Brazil, see LGPD and art. 154-A of the Penal Code). The
absence of Row Level Security is not authorization. You are responsible for your use of this
tool.

## Handling of secrets found

Any credential discovered in a bundle or file is **redacted** before it appears in output
and is **never transmitted anywhere** — in particular, it is never used to call the issuing
provider's API. Reporting a secret is safe; exercising it is not, and this tool does not.

## Reporting a vulnerability in stackaudit

Please report security issues privately to **helhinho10@gmail.com** rather than opening a
public issue. Include steps to reproduce and the version (`stackaudit --version`).
