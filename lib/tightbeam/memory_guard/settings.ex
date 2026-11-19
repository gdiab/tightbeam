defmodule Tightbeam.MemoryGuard.Settings do
  @moduledoc """
  Per-host memory-guard settings (memory limits v1.1 R17, R17a; build rulings
  NB-1 and NB-3: the resident cap and the session `oom_score_adj` are host
  configuration, not code).

  One row per (host, setting) in `host_memory_settings`, written only by an
  admin through `host-memory-set`, with actor and time. A host with no row for
  a setting uses its default, computed from the host's `MemTotal` read at
  gateway start, so the defaults are safe on any machine size:

  | Setting              | Default                              | Allowed                      |
  |----------------------|--------------------------------------|------------------------------|
  | `mode`               | `auto`                               | `auto`, `off`                |
  | `budget`             | 50% of MemTotal                      | 10%–90% of MemTotal          |
  | `sessionLimit`       | 20% of MemTotal, at most `budget`    | 512 MiB – `budget`           |
  | `residentCap`        | max(2, ⌊budget / 1 GiB⌋)             | 1–256                        |
  | `floorHold`          | 12 (%)                               | 3–50                         |
  | `floorRelease`       | 15 (%)                               | above `floorHold`, ≤ 60      |
  | `sessionOomScoreAdj` | 100                                  | 0–1000                       |

  `sessionOomScoreAdj` is the amount a session process raises its own
  `oom_score_adj` above the value it inherits from the gateway (v1.4 R14:
  +100; the shared adapter is never written).

  `budget` and `sessionLimit` are stored either as a percentage of MemTotal
  (`"50%"`) or as bytes (`"17179869184"`, written from `16G`). The effective
  settings are recomputed on every read, so a change applies to the next
  decision without a restart (R17a); a session tree keeps the `sessionLimit`
  it was launched with.
  """

  alias Tightbeam.DB
  alias Tightbeam.DB.Txn

  @ddl """
  CREATE TABLE IF NOT EXISTS host_memory_settings (
    host  TEXT NOT NULL CHECK(length(trim(host)) > 0),
    name  TEXT NOT NULL CHECK(name IN ('mode','budget','sessionLimit','residentCap',
                                       'floorHold','floorRelease','sessionOomScoreAdj')),
    value TEXT NOT NULL,
    setBy TEXT NOT NULL,
    setAt INTEGER NOT NULL,
    PRIMARY KEY (host, name)
  )
  """

  @names ~w(mode budget sessionLimit residentCap floorHold floorRelease sessionOomScoreAdj)
  @gib 1024 * 1024 * 1024
  @mib 1024 * 1024
  @min_session_limit 512 * @mib

  @type effective :: %{
          mode: String.t(),
          budget: non_neg_integer() | nil,
          session_limit: non_neg_integer() | nil,
          resident_cap: pos_integer() | nil,
          floor_hold: number(),
          floor_release: number(),
          session_oom_score_adj: 0..1000,
          mem_total: non_neg_integer() | nil,
          explicit: [String.t()],
          invalid: [%{name: String.t(), value: String.t(), reason: String.t()}]
        }

  @doc "Create the settings table (additive; no stamp change)."
  @spec ensure_schema(DB.server()) :: :ok | {:error, term()}
  def ensure_schema(db \\ DB), do: DB.execute(db, @ddl)

  @doc "The setting names `host-memory-set` accepts."
  def names, do: @names

  @doc "The stored rows of `host`: `%{name => %{value, set_by, set_at}}`."
  @spec stored(DB.server() | Txn.t(), String.t()) :: %{optional(String.t()) => map()}
  def stored(%Txn{} = txn, host), do: rows_to_map(Txn.q(txn, select_sql(), [host]))

  def stored(db, host) do
    {:ok, rows} = DB.query(db, select_sql(), [host])
    rows_to_map(rows)
  end

  defp select_sql, do: "SELECT name,value,setBy,setAt FROM host_memory_settings WHERE host=?1"

  defp rows_to_map(rows) do
    Map.new(rows, fn [name, value, set_by, set_at] ->
      {name, %{value: value, set_by: set_by, set_at: set_at}}
    end)
  end

  @doc """
  The effective settings of a host from its stored rows and its `MemTotal`
  (bytes, or nil when unknown, as on a remote host). A stored value that is no
  longer valid for this host (for example a byte budget above 90% of a smaller
  machine) is reported under `:invalid` and its default is used instead.
  """
  @spec effective(%{optional(String.t()) => map()}, non_neg_integer() | nil) :: effective()
  def effective(stored, mem_total) do
    values = Map.new(stored, fn {name, %{value: value}} -> {name, value} end)

    case resolve(values, mem_total) do
      {:ok, effective} ->
        Map.merge(effective, %{explicit: Enum.sort(Map.keys(values)), invalid: []})

      {:error, _} ->
        # Drop each stored value that does not validate on its own against the
        # defaults, then resolve what remains.
        {kept, invalid} =
          Enum.reduce(Enum.sort(values), {%{}, []}, fn {name, value}, {kept, invalid} ->
            case resolve(Map.put(kept, name, value), mem_total) do
              {:ok, _} -> {Map.put(kept, name, value), invalid}
              {:error, reason} -> {kept, [%{name: name, value: value, reason: reason} | invalid]}
            end
          end)

        {:ok, effective} = resolve(kept, mem_total)

        Map.merge(effective, %{
          explicit: Enum.sort(Map.keys(kept)),
          invalid: Enum.reverse(invalid)
        })
    end
  end

  @doc """
  Set `name` to `value` on `host` as `actor`, after validating the whole
  resulting set against the host's `MemTotal`. Returns the canonical stored row.
  """
  @spec set_in_txn(
          Txn.t(),
          String.t(),
          String.t(),
          String.t(),
          String.t(),
          non_neg_integer() | nil
        ) ::
          {:ok, map()} | {:error, map()}
  def set_in_txn(%Txn{} = txn, host, name, value, actor, mem_total) do
    with {:ok, canonical} <- canonical(name, value),
         current = Map.new(stored(txn, host), fn {n, %{value: v}} -> {n, v} end),
         {:ok, _effective} <- validate_set(Map.put(current, name, canonical), mem_total) do
      set_at = System.system_time(:millisecond)

      Txn.q(
        txn,
        """
        INSERT INTO host_memory_settings (host,name,value,setBy,setAt) VALUES (?1,?2,?3,?4,?5)
        ON CONFLICT(host,name) DO UPDATE SET
          value=excluded.value, setBy=excluded.setBy, setAt=excluded.setAt
        """,
        [host, name, canonical, actor, set_at]
      )

      {:ok, %{host: host, name: name, value: canonical, set_by: actor, set_at: set_at}}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, %{code: "invalid_setting", message: "#{name}: #{reason}"}}
    end
  end

  defp validate_set(values, mem_total) do
    if is_nil(mem_total) and Enum.any?(["budget", "sessionLimit"], &Map.has_key?(values, &1)) and
         Enum.any?(["budget", "sessionLimit"], &percent?(Map.get(values, &1))) do
      {:error, "a percentage needs the host's memory size, which is unknown for this host"}
    else
      resolve(values, mem_total)
    end
  end

  defp percent?(nil), do: false
  defp percent?(value), do: String.ends_with?(value, "%")

  ## Canonical values

  @doc false
  @spec canonical(String.t(), String.t()) :: {:ok, String.t()} | {:error, String.t()}
  def canonical(name, value) when is_binary(name) and is_binary(value) do
    value = String.trim(value)

    case name do
      "mode" when value in ["auto", "off"] -> {:ok, value}
      "mode" -> {:error, "must be auto or off"}
      size when size in ["budget", "sessionLimit"] -> canonical_size(value)
      "residentCap" -> canonical_integer(value)
      "sessionOomScoreAdj" -> canonical_integer(value)
      percent when percent in ["floorHold", "floorRelease"] -> canonical_percent(value)
      _ -> {:error, "unknown setting; one of #{Enum.join(@names, ", ")}"}
    end
  end

  defp canonical_size(value) do
    cond do
      String.ends_with?(value, "%") ->
        with {:ok, number} <- parse_number(String.trim_trailing(value, "%")),
             do: {:ok, format_number(number) <> "%"}

      true ->
        case Regex.run(~r/^(\d+)\s*([KMGT]i?B?|B)?$/i, value) do
          [_, digits] ->
            {:ok, digits |> String.to_integer() |> Integer.to_string()}

          [_, digits, unit] ->
            {:ok, Integer.to_string(String.to_integer(digits) * unit_bytes(unit))}

          nil ->
            {:error, "must be a percentage of memory (50%) or a size (16G, 512M, bytes)"}
        end
    end
  end

  defp unit_bytes(unit) do
    case unit |> String.upcase() |> String.first() do
      "B" -> 1
      "K" -> 1024
      "M" -> @mib
      "G" -> @gib
      "T" -> 1024 * @gib
    end
  end

  defp canonical_integer(value) do
    case Integer.parse(value) do
      {integer, ""} -> {:ok, Integer.to_string(integer)}
      _ -> {:error, "must be a whole number"}
    end
  end

  defp canonical_percent(value) do
    with {:ok, number} <- parse_number(String.trim_trailing(value, "%")),
         do: {:ok, format_number(number)}
  end

  defp parse_number(text) do
    case Float.parse(text) do
      {number, ""} -> {:ok, number}
      _ -> {:error, "must be a number"}
    end
  end

  defp format_number(number) when is_float(number) do
    if number == Float.round(number),
      do: Integer.to_string(trunc(number)),
      else: Float.to_string(number)
  end

  ## Resolution with the R17 ranges

  defp resolve(values, mem_total) do
    with {:ok, budget} <- budget(values, mem_total),
         {:ok, session_limit} <- session_limit(values, mem_total, budget),
         {:ok, resident_cap} <- resident_cap(values, budget),
         {:ok, floor_hold} <- percent_in(values, "floorHold", 12, 3, 50),
         {:ok, floor_release} <- floor_release(values, floor_hold),
         {:ok, oom} <- integer_in(values, "sessionOomScoreAdj", 100, 0, 1000) do
      {:ok,
       %{
         mode: Map.get(values, "mode", "auto"),
         budget: budget,
         session_limit: session_limit,
         resident_cap: resident_cap,
         floor_hold: floor_hold,
         floor_release: floor_release,
         session_oom_score_adj: oom,
         mem_total: mem_total
       }}
    end
  end

  defp budget(values, mem_total) do
    case {Map.get(values, "budget"), mem_total} do
      {nil, nil} ->
        {:ok, nil}

      {nil, total} ->
        {:ok, div(total, 2)}

      {value, total} ->
        size_in(value, total, "budget", fn bytes -> range_of_total(bytes, total) end)
    end
  end

  defp range_of_total(_bytes, nil), do: :ok

  defp range_of_total(bytes, total) do
    if bytes >= div(total, 10) and bytes <= div(total * 9, 10),
      do: :ok,
      else: {:error, "must be between 10% and 90% of this host's memory"}
  end

  defp session_limit(values, mem_total, budget) do
    case Map.get(values, "sessionLimit") do
      nil when is_nil(mem_total) ->
        {:ok, nil}

      nil ->
        {:ok, min(div(mem_total, 5), budget)}

      value ->
        size_in(value, mem_total, "sessionLimit", fn bytes ->
          cond do
            bytes < @min_session_limit -> {:error, "must be at least 512 MiB"}
            is_integer(budget) and bytes > budget -> {:error, "must not exceed budget"}
            true -> :ok
          end
        end)
    end
  end

  defp size_in(value, total, _name, check) do
    bytes =
      if String.ends_with?(value, "%") do
        {percent, ""} = Float.parse(String.trim_trailing(value, "%"))
        if total, do: trunc(total * percent / 100)
      else
        String.to_integer(value)
      end

    cond do
      is_nil(bytes) -> {:error, "a percentage needs the host's memory size"}
      true -> with :ok <- check.(bytes), do: {:ok, bytes}
    end
  end

  defp resident_cap(values, budget) do
    case Map.get(values, "residentCap") do
      nil when is_nil(budget) -> {:ok, nil}
      nil -> {:ok, max(2, div(budget, @gib))}
      value -> integer_in(%{"residentCap" => value}, "residentCap", nil, 1, 256)
    end
  end

  defp percent_in(values, name, default, low, high) do
    case Map.get(values, name) do
      nil ->
        {:ok, default}

      value ->
        {number, ""} = Float.parse(value)

        if number >= low and number <= high,
          do: {:ok, normalize(number)},
          else: {:error, "#{name} must be between #{low}% and #{high}%"}
    end
  end

  defp floor_release(values, floor_hold) do
    case Map.get(values, "floorRelease") do
      nil ->
        if floor_hold < 15,
          do: {:ok, 15},
          else: {:error, "floorRelease must be above floorHold"}

      value ->
        {number, ""} = Float.parse(value)

        cond do
          number <= floor_hold -> {:error, "floorRelease must be above floorHold"}
          number > 60 -> {:error, "floorRelease must be at most 60%"}
          true -> {:ok, normalize(number)}
        end
    end
  end

  defp integer_in(values, name, default, low, high) do
    case Map.get(values, name) do
      nil ->
        {:ok, default}

      value ->
        integer = String.to_integer(value)

        if integer >= low and integer <= high,
          do: {:ok, integer},
          else: {:error, "#{name} must be between #{low} and #{high}"}
    end
  end

  defp normalize(number) when is_float(number),
    do: if(number == Float.round(number), do: trunc(number), else: number)

  defp normalize(number), do: number
end
