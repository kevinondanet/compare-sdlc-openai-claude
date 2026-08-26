# Architecture context

Bounded context: the `tickets` package (in-memory service + JSON-store CLI). No other
component consumes it; the CLI is the only interface (IFC-001). The change touches the
record shape (`Ticket.priority`), the listing query and the CLI argument parser.
