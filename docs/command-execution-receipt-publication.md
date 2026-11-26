# Command execution receipt publication

Rust and Elixir command-execution JSON writers use the same protocol. A writer
creates an exclusive `.<final-name>.tmp-<pid>-<nonce>` file in the final file's
directory, writes the complete JSON plus its trailing newline, flushes the file,
and closes it. It then creates the final name as a hard link to that flushed
inode. Hard-link creation is the atomic publication point and refuses with
`EEXIST` when the final name already exists; receipts are never overwritten and
duplicate content is not treated as idempotent success.

After publication, the writer flushes the parent directory, removes its temp
name, and flushes the directory again before returning success. Thus a successful
return covers both durable final evidence and durable temp cleanup. A crash before
publication can leave only a temp name. A crash after publication can leave both
names pointing to the same complete inode. Readers open only the exact final paths
recorded in the execution manifest, so temp names are never evidence and may be
removed as debris.

The plain-text single-use claim file is outside this protocol: creating its final
name is itself the claim operation. The held-writer test seam pauses JSON writers
after the temp file is flushed and before its hard link is created.
