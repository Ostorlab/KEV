# Contributing to KEV

Thanks for helping improve KEV. Most contributions add a detector for a newly exploited vulnerability, fix a false
positive in an existing template, or improve the documentation.

## Before you start

- Check the [Current Coverage](README.md#current-coverage) table and open issues to make sure the vulnerability isn't
  already covered or in progress.
- For a new detector, open an issue first with the CVE ID and a public reference (CISA KEV entry, vendor advisory or
  write-up) so we can agree on the approach.
- **Do not report security vulnerabilities in public issues.** Email `security@ostorlab.co` instead.

## Adding a Nuclei detector

1. Add the template to `nuclei/` and name it after the vulnerability ID, for example `nuclei/CVE-2025-12345.yaml`.
   Follow the structure of the existing templates: `id`, `info` (name, severity, description, remediation, references,
   classification) and include the `kev` tag when the CVE is in the CISA KEV catalog.
2. Reference it in `agent_group.yaml` under the `agent/ostorlab/nuclei` agent's `template_urls`, using the raw GitHub
   URL of the file on the `main` branch, like the existing entries.
3. Add a row at the top of the [Current Coverage](README.md#current-coverage) table with the ID, the source of the
   detector (official, modified or custom template) and the date.
4. Prefer detection that confirms the vulnerability without side effects. A template must not modify data, create
   accounts or leave artifacts on the target.

Detectors that need more than a Nuclei template (multi-step exploits, custom protocols) live in
[Agent Asteroid](https://github.com/Ostorlab/agent_asteroid); open the pull request there and reference it here.

## Testing your change

Install the CLI and run the agent group against a target you own or are authorized to test, ideally a vulnerable lab
instance of the affected product:

```shell
pip install -U ostorlab
ostorlab scan run --install -g agent_group.yaml link --url https://your-test-target --method GET
ostorlab vulnz list -s <scan-id>
```

Confirm the detector reports the vulnerable target and stays silent on a patched one. Mention both results in the pull
request.

## Pull requests

- Keep one detector or fix per pull request.
- The title must follow the semantic format checked by CI and start with `feature:`, `fix:` or `documentation:`, for
  example `feature: add CVE-2025-12345 detector`.
- Describe the vulnerability, the references you used and how you tested it.

## Questions

Open an issue, or see the [OXO documentation](https://oxo.ostorlab.co/docs) for how agent groups work. KEV is
maintained by [Ostorlab](https://ostorlab.co).
