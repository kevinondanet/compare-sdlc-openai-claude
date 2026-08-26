# Architecture context

The lunch-order form is a **generated application**: the office manager describes the
form in `forms/lunch-order.json`; `python -m lowcode.generator` renders
`lowcode/generated/lunch_order.py`, a thin module over the shared engine (`lowcode.schema`
for validation and the cut-off, `lowcode.table` for the table and CSV export,
`lowcode.app` for submissions and the generic command line). Nothing outside `lowcode/`
depends on the generated module.
