# Skills extension schema (vendored test data)

`schema.json` is `schema/beta/schema.json` of
<https://github.com/modelcontextprotocol/ext-skills>, copied unchanged at
commit `92eca3c51d8ccb2200d573c26634350436f70a00`. It is licensed under
Apache-2.0 by the MCP project (see that repository's `LICENSE`).

`skills_tests.rs` validates the gateway's `skills/list`, `skills/get` and
`resources/directory/read` answers against its `$defs`. To update it, copy
the file again from a newer commit and change the commit above.
