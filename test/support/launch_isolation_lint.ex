defmodule Tightbeam.LaunchIsolationLint do
  @moduledoc false

  # F1 (wi_34a7be66) L4: every process launch in code the suite runs goes through
  # Tightbeam.TestIsolation, or is a reviewed exception in
  # test/support/process_launch_allowlist.exs.
  #
  # Parse set: test/** plus every Elixir file a test runs from elsewhere, i.e.
  # loaded into the VM (Code.require_file/eval_file/compile_file with a literal
  # path) or run through Tightbeam.TestIsolation.run_script!/3 with a literal
  # path, followed transitively.
  #
  # A test runs a file outside test/ only through run_script!/3 with a literal
  # path. Any other call that is handed a script outside test/ (a literal, or an
  # attribute or variable bound to one in the same file) is reported unless the
  # call only reads it; a non-literal run_script!/3 path is reported.
  #
  # A launch that runs at compile time (a module attribute value, a module or
  # describe body outside a function, test or callback, the top level of an .ex
  # file) runs before the preflight, so it can never be allowlisted.

  @isolation "test/support/test_isolation.ex"
  @allowlist "test/support/process_launch_allowlist.exs"

  @runtime_blocks ~w(def defp defmacro defmacrop test setup setup_all)a

  @doc "Every violation in the repository rooted at `root`."
  def violations(root) do
    files = parse_set(root)
    sources = Map.new(files, &{&1, File.read!(Path.join(root, &1))})
    allowlist = load_allowlist(root)
    violations_in(sources, allowlist)
  end

  @doc """
  Violations for `sources` (relative path => source) against `allowlist`
  (a list of maps with :file, :function, :kind, :reason, :reviewer).
  """
  def violations_in(sources, allowlist) do
    findings =
      sources
      |> Enum.reject(fn {file, _} -> file == @isolation end)
      |> Enum.flat_map(fn {file, source} ->
        launches(file, source) ++
          script_executions(file, source) ++
          privilege_launches(file, source) ++ environment_gates(file, source)
      end)

    keys = MapSet.new(allowlist, &{&1.file, &1.function, &1.kind})

    {fatal, findings} = Enum.split_with(findings, &(&1.function == :fatal))
    {compile_time, runtime} = Enum.split_with(findings, &(&1.function == :compile_time))

    runtime =
      Enum.map(runtime, &if(&1.function == :script, do: %{&1 | function: "script"}, else: &1))

    unlisted =
      for f <- runtime, not MapSet.member?(keys, {f.file, f.function, f.kind}) do
        "#{f.file}:#{f.line} #{f.kind} in #{f.function} does not go through " <>
          "Tightbeam.TestIsolation and is not on #{@allowlist}"
      end

    compile =
      for f <- compile_time do
        "#{f.file}:#{f.line} #{f.kind} runs at compile time, before the preflight; " <>
          "it cannot be allowlisted"
      end

    found = MapSet.new(runtime, &{&1.file, &1.function, &1.kind})

    stale =
      for entry <- allowlist,
          not MapSet.member?(found, {entry.file, entry.function, entry.kind}) do
        "stale #{@allowlist} entry: #{entry.file} #{entry.function} #{entry.kind}"
      end

    # The reviewer field names the reviewing session and its verdict: a
    # Tightbeam session id (s_ and 8 hex digits) and a verdict attest id (att_ and
    # at least 8 hex digits). Anything else, including an entry still awaiting
    # review, is not attributable (reviewer findings B4 and, on 2a49ae5e, B3).
    malformed =
      for entry <- allowlist, not reviewed_entry?(entry) do
        "#{@allowlist} entry #{entry.file} #{entry.function} needs a reason and a reviewer " <>
          "naming a reviewing session (s_…) and its verdict (att_…), not pending"
      end

    fatal = for f <- fatal, do: "#{f.file}:#{f.line} #{f.kind}; it cannot be allowlisted"

    Enum.sort(unlisted ++ compile ++ stale ++ malformed ++ fatal)
  end

  @doc "Whether an allowlist entry has a reason and an attributable review."
  def reviewed_entry?(entry) do
    reviewer = entry[:reviewer]

    is_binary(entry[:reason]) and String.trim(entry.reason) != "" and is_binary(reviewer) and
      Regex.match?(~r/\bs_[0-9a-f]{8}\b/, reviewer) and
      Regex.match?(~r/\batt_[0-9a-f]{8}/, reviewer) and not Regex.match?(~r/pending/i, reviewer)
  end

  @doc "The relative paths the lint parses, for `root`."
  def parse_set(root) do
    # F1 erratum 2 C6 (and its N1): config evaluation runs before the preflight in
    # test_helper.exs, so every config file joins the parse set.
    tests =
      (Path.wildcard(Path.join(root, "test/**/*.{ex,exs}")) ++
         Path.wildcard(Path.join(root, "config/*.exs")))
      |> Enum.map(&Path.relative_to(&1, root))

    follow(root, tests, MapSet.new(tests))
  end

  defp follow(_root, [], seen), do: seen |> MapSet.to_list() |> Enum.sort()

  defp follow(root, [file | rest], seen) do
    found =
      root
      |> Path.join(file)
      |> File.read!()
      |> executed_elixir(root)
      |> Enum.reject(&MapSet.member?(seen, &1))

    follow(root, rest ++ found, Enum.into(found, seen))
  end

  @loaders [:require_file, :eval_file, :compile_file, :compile_quoted, :compile_string]

  # Elixir files outside test/ this source executes: loaded into the VM by
  # Code.require_file/eval_file/compile_file, or run with run_script!/3.
  defp executed_elixir(source, root) do
    case Code.string_to_quoted(source) do
      {:ok, ast} ->
        {_ast, paths} =
          Macro.prewalk(ast, [], fn
            {{:., _, [{:__aliases__, _, [:Code]}, loader]}, _, args} = node, acc
            when loader in @loaders ->
              {node, script_literals(args) ++ acc}

            {{:., _, [{:__aliases__, _, [:Tightbeam, :TestIsolation]}, :run_script!]}, _,
             [path | _]} = node,
            acc ->
              {node, script_literals(path) ++ acc}

            node, acc ->
              {node, acc}
          end)

        paths
        |> Enum.filter(&String.ends_with?(&1, [".ex", ".exs"]))
        |> Enum.uniq()
        |> Enum.filter(&File.regular?(Path.join(root, &1)))

      {:error, _} ->
        []
    end
  end

  @script_path ~r{(?:\.\./)*((?:scripts|packaging|priv|cli)/[A-Za-z0-9_./-]+\.(?:exs|ex|sh|py|js|mjs|rb|pl))}

  @doc false
  def script_literals(ast) do
    {_ast, found} =
      Macro.prewalk(ast, [], fn
        literal, acc when is_binary(literal) ->
          {literal, Regex.scan(@script_path, literal, capture: :all_but_first) ++ acc}

        node, acc ->
          {node, acc}
      end)

    found |> List.flatten() |> Enum.uniq()
  end

  defp load_allowlist(root) do
    path = Path.join(root, @allowlist)

    if File.regular?(path) do
      {entries, _} = Code.eval_file(path)
      entries
    else
      []
    end
  end

  # Calls that may be handed a script path without running it.
  @readers [
    :File,
    :Path,
    :String,
    :Regex,
    :IO,
    :Enum,
    :Map,
    :List,
    :Keyword,
    :Base,
    :JSON,
    :Jason,
    :Kernel,
    :MapSet,
    :Stream,
    :Macro,
    :URI,
    :Application
  ]
  @reader_calls [
    :=~,
    :<>,
    :assert,
    :refute,
    :to_string,
    :inspect,
    :==,
    :!=,
    :in,
    :++,
    :|>,
    :=,
    :{},
    :%{},
    :__block__,
    :sigil_s,
    :sigil_S,
    :__aliases__,
    :.,
    :<<>>,
    :"::",
    :->,
    :@,
    :external_resource,
    :when,
    :case,
    :cond,
    :if,
    :unless,
    :def,
    :defp,
    :defmodule,
    :do,
    :fn,
    :with,
    :for
  ]

  @doc "Calls handed a script outside test/ other than through run_script!/3."
  def script_executions(file, source) do
    case Code.string_to_quoted(source, file: file, columns: false) do
      {:ok, ast} ->
        bound = script_bindings(ast)

        {_ast, acc} =
          Macro.prewalk(ast, [], fn node, acc -> {node, execution(node, file, bound) ++ acc} end)

        acc

      {:error, _} ->
        []
    end
  end

  # Module attributes and variables bound (anywhere in the file) to an
  # expression naming a script outside test/.
  defp script_bindings(ast) do
    {_ast, bound} =
      Macro.prewalk(ast, %{}, fn
        {:@, _, [{name, _, [value]}]} = node, acc when is_atom(name) ->
          {node, bind(acc, {:attr, name}, value)}

        {:=, _, [{name, _, ctx}, value]} = node, acc when is_atom(name) and is_atom(ctx) ->
          {node, bind(acc, {:var, name}, value)}

        {:defp, _, [{name, _, _}, [do: value]]} = node, acc when is_atom(name) ->
          {node, bind(acc, {:call, name}, value)}

        {:def, _, [{name, _, _}, [do: value]]} = node, acc when is_atom(name) ->
          {node, bind(acc, {:call, name}, value)}

        node, acc ->
          {node, acc}
      end)

    bound
  end

  defp bind(acc, key, value) do
    case script_literals(value) do
      [] -> acc
      scripts -> Map.update(acc, key, scripts, &Enum.uniq(&1 ++ scripts))
    end
  end

  defp references(args, bound) do
    {_ast, refs} =
      Macro.prewalk(args, [], fn
        {:@, _, [{name, _, ctx}]} = node, acc when is_atom(name) and is_atom(ctx) ->
          {node, Map.get(bound, {:attr, name}, []) ++ acc}

        {name, _, ctx} = node, acc when is_atom(name) and is_atom(ctx) ->
          {node, Map.get(bound, {:var, name}, []) ++ acc}

        {name, _, []} = node, acc when is_atom(name) ->
          {node, Map.get(bound, {:call, name}, []) ++ acc}

        node, acc ->
          {node, acc}
      end)

    Enum.uniq(script_literals(args) ++ refs)
  end

  defp execution(
         {{:., meta, [{:__aliases__, _, [:Tightbeam, :TestIsolation]}, :run_script!]}, _, args},
         file,
         _bound
       ) do
    case args do
      [path | _] when is_binary(path) ->
        []

      _ ->
        [
          %{
            file: file,
            line: Keyword.get(meta, :line, 0),
            kind: "run_script!/3 with a non-literal path",
            function: :fatal
          }
        ]
    end
  end

  # Code loads files (the parse set follows them) or reads source; neither runs a
  # process.
  defp execution({{:., _, [{:__aliases__, _, [:Code]}, _fun]}, _, _}, _file, _bound),
    do: []

  defp execution({{:., _, [{:__aliases__, _, [module | _]}, _fun]}, _, _}, _file, _bound)
       when module in @readers,
       do: []

  defp execution({{:., meta, [_module, fun]}, _, args}, file, bound)
       when is_atom(fun) and is_list(args),
       do: executed_scripts(meta, fun, args, file, bound)

  defp execution({fun, meta, args}, file, bound)
       when is_atom(fun) and is_list(args) and fun not in @reader_calls,
       do: executed_scripts(meta, fun, args, file, bound)

  defp execution(_node, _file, _bound), do: []

  # Only direct arguments count; nested calls are visited on their own.
  defp executed_scripts(meta, fun, args, file, bound) do
    direct =
      Enum.flat_map(args, fn
        arg when is_binary(arg) -> script_literals(arg)
        arg when is_list(arg) -> Enum.flat_map(arg, &direct_ref(&1, bound))
        arg -> direct_ref(arg, bound)
      end)
      |> Enum.uniq()

    for script <- direct do
      %{
        file: file,
        line: Keyword.get(meta, :line, 0),
        kind: "runs #{script} outside run_script!/3 (#{fun})",
        function: :script
      }
    end
  end

  defp direct_ref(arg, _bound) when is_binary(arg), do: script_literals(arg)

  defp direct_ref({:@, _, [{_name, _, ctx}]} = arg, bound) when is_atom(ctx),
    do: references(arg, bound)

  defp direct_ref({name, _, ctx} = arg, bound) when is_atom(name) and is_atom(ctx),
    do: references(arg, bound)

  defp direct_ref({name, _, []} = arg, bound) when is_atom(name), do: references(arg, bound)
  defp direct_ref(_arg, _bound), do: []

  @doc "Every launch in one file: %{file, line, kind, function}."
  def launches(file, source) do
    case Code.string_to_quoted(source, file: file, columns: false) do
      {:ok, ast} ->
        top = if String.ends_with?(file, ".ex"), do: :compile_time, else: "top level"
        walk(ast, %{file: file, scope: top}, [])

      {:error, error} ->
        [%{file: file, line: 0, kind: "unparseable #{inspect(error)}", function: :compile_time}]
    end
  end

  defp walk({:defmodule, _, [_name, [do: body]]}, ctx, acc),
    do: walk(body, %{ctx | scope: :compile_time}, acc)

  defp walk({kind, _, [head | rest]}, ctx, acc) when kind in @runtime_blocks do
    walk([head | rest], %{ctx | scope: block_name(kind, head)}, acc)
  end

  defp walk({:@, _, [{_name, _, value}]}, %{scope: :compile_time} = ctx, acc),
    do: walk(value, ctx, acc)

  defp walk({:describe, _, [_name, [do: body]]}, ctx, acc),
    do: walk(body, %{ctx | scope: :compile_time}, acc)

  # A function or quoted template runs later, at runtime.
  defp walk({:fn, _, clauses}, %{scope: :compile_time} = ctx, acc),
    do: walk(clauses, %{ctx | scope: "anonymous fn"}, acc)

  defp walk({:quote, _, _} = _quoted, _ctx, acc), do: acc

  # Calls through the isolation helper are the sanctioned path; their spawn
  # tuples are its arguments, not separate launches.
  defp walk(
         {{:., _, [{:__aliases__, _, [:Tightbeam, :TestIsolation]}, _fun]}, _, args},
         ctx,
         acc
       ),
       do: walk_args_skipping_tuples(args, ctx, acc)

  defp walk({{:., meta, [module, fun]}, _, args} = _call, ctx, acc) do
    acc =
      case launch_kind(module, fun) do
        nil -> acc
        kind -> [finding(ctx, meta, kind) | acc]
      end

    walk(args, ctx, acc)
  end

  defp walk({spawn, target}, ctx, acc) when spawn in [:spawn_executable, :spawn] do
    walk(target, ctx, [finding(ctx, [], "{:#{spawn}, _} port")] ++ acc)
  end

  defp walk({form, _meta, args}, ctx, acc) when is_list(args), do: walk([form | args], ctx, acc)
  defp walk({left, right}, ctx, acc), do: walk(right, ctx, walk(left, ctx, acc))
  defp walk(list, ctx, acc) when is_list(list), do: Enum.reduce(list, acc, &walk(&1, ctx, &2))
  defp walk(_other, _ctx, acc), do: acc

  defp walk_args_skipping_tuples(args, ctx, acc) do
    Enum.reduce(args, acc, fn
      {spawn, target}, acc when spawn in [:spawn_executable, :spawn] -> walk(target, ctx, acc)
      arg, acc -> walk(arg, ctx, acc)
    end)
  end

  # F1 erratum 1 rev 4 L4: a privilege-raising launch can never be allowlisted:
  # the tool as a launch's executable, as the first element of a prefix list
  # handed to a launch or a launch helper (`prefix: ["sudo", ...]`), or as a word
  # in a command string handed to a shell launch. An argument vector compared as
  # data, or an executable name matched inside a test command runner, is not a
  # launch.
  @privilege_tools ~w(sudo su doas pkexec)
  @shell_tools ~w(sh bash dash zsh)

  @doc "Privilege-raising launches in one file (never allowlistable)."
  def privilege_launches(file, source) do
    case Code.string_to_quoted(source, file: file, columns: false) do
      {:ok, ast} ->
        {_ast, found} =
          Macro.prewalk(ast, [], fn node, acc -> {node, privilege_node(node, file) ++ acc} end)

        found

      {:error, _} ->
        []
    end
  end

  defp privilege_node({{:., meta, [module, fun]}, _, [command | rest]}, file) do
    if launch_kind(module, fun) || match?({:__aliases__, _, [:Tightbeam, :TestIsolation]}, module) do
      privilege_command(command, rest, meta, file)
    else
      prefix_option(rest, meta, file)
    end
  end

  # A variable bound to an argument vector that starts with a privilege tool is a
  # launch prefix in waiting (P5c's `sudo = ["sudo", "-n", ...]`).
  defp privilege_node({:=, meta, [{var, _, ctx}, [first | _]]}, file)
       when is_atom(var) and is_atom(ctx) and is_binary(first) do
    if privilege_tool?(first),
      do: [fatal(file, meta, "privilege-raising argument vector bound to #{var}")],
      else: []
  end

  defp privilege_node({fun, meta, args}, file) when is_atom(fun) and is_list(args),
    do: prefix_option(args, meta, file)

  defp privilege_node(_node, _file), do: []

  defp privilege_command(command, rest, meta, file) do
    args = List.first(rest)

    cond do
      privilege_tool?(command) ->
        [fatal(file, meta, "privilege-raising launch of #{inspect(command)}")]

      is_binary(command) and Path.basename(command) in @shell_tools and is_list(args) ->
        for arg <- args, is_binary(arg), String.match?(arg, privilege_word()),
            do: fatal(file, meta, "privilege-raising tool inside a shell command string")

      is_list(args) and match?([first | _] when is_binary(first), args) and
          privilege_tool?(hd(args)) ->
        [fatal(file, meta, "privilege-raising tool as a launched argument vector")]

      true ->
        prefix_option(rest, meta, file)
    end
  end

  defp prefix_option(args, meta, file) do
    for arg <- List.wrap(args),
        is_list(arg),
        {key, value} <- arg,
        key in [:prefix, :wrapper, :exec_prefix],
        match?([first | _] when is_binary(first), value),
        privilege_tool?(hd(value)),
        do: fatal(file, meta, "privilege-raising tool as a launch prefix (#{key}:)")
  end

  defp privilege_tool?(name) when is_binary(name), do: Path.basename(name) in @privilege_tools
  defp privilege_tool?(_name), do: false

  defp privilege_word, do: ~r/(^|[\s;&|(`'"])(?:\/usr\/bin\/|\/bin\/)?(sudo|su|doas|pkexec)(\s|$)/

  # F1 erratum 1 rev 4 L4: no test is tagged, skipped, configured or selected on
  # CI, GITHUB_ACTIONS, a RUNNER_* variable or a privilege probe. Such a gate
  # silently drops coverage under the sandbox (it passes neither), so it is never
  # allowlistable. Reads elsewhere (for example the authoritative-gate check in
  # test_helper.exs) are not gates.
  @doc "Environment or privilege gates in one file (never allowlistable)."
  def environment_gates(file, source) do
    case Code.string_to_quoted(source, file: file, columns: false) do
      {:ok, ast} ->
        {_ast, found} =
          Macro.prewalk(ast, [], fn
            {:@, meta, [{name, _, [value]}]} = node, acc when is_atom(name) ->
              {node, gate_reads(value, meta, file, "module attribute @#{name}") ++ acc}

            {{:., meta, [{:__aliases__, _, [:ExUnit]}, fun]}, _, args} = node, acc
            when fun in [:start, :configure] ->
              {node, gate_reads(args, meta, file, "ExUnit.#{fun} options") ++ acc}

            node, acc ->
              {node, acc}
          end)

        found

      {:error, _} ->
        []
    end
  end

  defp gate_reads(ast, meta, file, where) do
    {_ast, found} =
      Macro.prewalk(ast, [], fn
        {{:., _, [{:__aliases__, _, [:System]}, fun]}, _, [name | _]} = node, acc
        when fun in [:get_env, :fetch_env, :fetch_env!] and is_binary(name) ->
          if gate_variable?(name),
            do: {node, [fatal(file, meta, "#{where} depends on #{name}") | acc]},
            else: {node, acc}

        {{:., _, [module, fun]}, _, [command | _]} = node, acc ->
          if launch_kind(module, fun) && privilege_tool?(command),
            do: {node, [fatal(file, meta, "#{where} depends on a privilege probe") | acc]},
            else: {node, acc}

        node, acc ->
          {node, acc}
      end)

    found
  end

  defp gate_variable?(name),
    do: name in ["CI", "GITHUB_ACTIONS"] or String.starts_with?(name, "RUNNER_")

  defp fatal(file, meta, kind),
    do: %{file: file, line: Keyword.get(meta, :line, 0), kind: kind, function: :fatal}

  defp launch_kind({:__aliases__, _, [:System]}, :cmd), do: "System.cmd"
  defp launch_kind({:__aliases__, _, [:System]}, :shell), do: "System.shell"
  defp launch_kind({:__aliases__, _, [:Port]}, :open), do: "Port.open"
  defp launch_kind(:erlang, :open_port), do: ":erlang.open_port"
  defp launch_kind(:os, :cmd), do: ":os.cmd"
  defp launch_kind(_module, _fun), do: nil

  defp finding(%{file: file, scope: scope}, meta, kind) do
    function = if scope == :compile_time, do: :compile_time, else: scope
    %{file: file, line: Keyword.get(meta, :line, 0), kind: kind, function: function}
  end

  defp block_name(kind, head) when kind in [:test, :setup, :setup_all] do
    case head do
      name when is_binary(name) -> "#{kind} #{name}"
      _ -> to_string(kind)
    end
  end

  defp block_name(kind, {:when, _, [head | _]}), do: block_name(kind, head)

  defp block_name(kind, {name, _, args}) when is_atom(name),
    do: "#{kind} #{name}/#{if is_list(args), do: length(args), else: 0}"

  defp block_name(kind, _head), do: to_string(kind)
end
