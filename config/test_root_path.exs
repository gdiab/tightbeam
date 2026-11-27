defmodule Tightbeam.TestRootPath do
  @moduledoc false

  # Both paths must already exist as directories. Resolve every link before
  # comparing path components so an alias of the root is accepted while a link
  # that leaves it, a sibling prefix, or an unresolved path refuses closed.
  def existing_directory_within?(path, root) when is_binary(path) and is_binary(root) do
    with {:ok, canonical_path} <- canonical_existing(path),
         {:ok, canonical_root} <- canonical_existing(root),
         true <- File.dir?(canonical_path),
         true <- File.dir?(canonical_root) do
      root_components = Path.split(canonical_root)
      path_components = Path.split(canonical_path)
      Enum.take(path_components, length(root_components)) == root_components
    else
      _ -> false
    end
  end

  defp canonical_existing(path, links_left \\ 40)
  defp canonical_existing(_path, 0), do: {:error, :excessive_links}
  defp canonical_existing("/", _links_left), do: {:ok, "/"}

  defp canonical_existing(path, links_left) do
    expanded = Path.expand(path)

    with {:ok, parent} <- canonical_existing(Path.dirname(expanded), links_left) do
      candidate = Path.join(parent, Path.basename(expanded))

      case File.lstat(candidate) do
        {:ok, %{type: :symlink}} ->
          with {:ok, target} <- File.read_link(candidate) do
            canonical_existing(Path.expand(target, parent), links_left - 1)
          end

        {:ok, _stat} ->
          {:ok, candidate}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end
end
