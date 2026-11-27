defmodule Tightbeam.TestRootPath do
  @moduledoc false

  # Both paths must already exist as directories. Resolve components in filesystem
  # order so `..` follows the physical parent of any preceding link. Comparing the
  # resulting components accepts a root alias while every escape refuses closed.
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

  defp canonical_existing(path) do
    case Path.split(path) do
      ["/" | components] -> resolve_components("/", components, 40)
      _ -> {:error, :not_absolute}
    end
  end

  defp resolve_components(current, [], _links_left), do: {:ok, current}

  defp resolve_components(current, ["." | rest], links_left),
    do: resolve_components(current, rest, links_left)

  defp resolve_components("/", [".." | rest], links_left),
    do: resolve_components("/", rest, links_left)

  defp resolve_components(current, [".." | rest], links_left),
    do: resolve_components(Path.dirname(current), rest, links_left)

  defp resolve_components(current, [component | rest], links_left) do
    candidate = Path.join(current, component)

    case File.lstat(candidate) do
      {:ok, %{type: :symlink}} when links_left == 0 ->
        {:error, :excessive_links}

      {:ok, %{type: :symlink}} ->
        with {:ok, target} <- File.read_link(candidate) do
          case Path.split(target) do
            ["/" | target_components] ->
              resolve_components("/", target_components ++ rest, links_left - 1)

            target_components ->
              resolve_components(current, target_components ++ rest, links_left - 1)
          end
        end

      {:ok, _stat} ->
        resolve_components(candidate, rest, links_left)

      {:error, reason} ->
        {:error, reason}
    end
  end
end
