defmodule MosquittoEmbed.Driver do
    use GenServer
    require Logger

    # These must be kept in sync with mosquitto_embed.c
    @cmd_echo 0
    @cmd_init 1
    @cmd_poll_period 2
    @cmd_open_client 3
    @cmd_subscribe 4

    @servername __MODULE__
    @portname_string 'mosquitto_embed'
    @portname :mosquitto_embed

    def start_link(args \\ []) do
        GenServer.start_link(__MODULE__, args, name: @servername)
    end

    def hello(msg) do
        :erlang.port_call(@portname, @cmd_echo, msg)
    end

    def subscribe(topic) do
        :erlang.port_call(@portname, @cmd_subscribe, topic)
    end

    def init(args) do
        # Make sure the driver is loaded 
        # (ignore any error if it already is)
        port_path = :code.priv_dir(:mosquitto_embed)
        case :erl_ddll.load_driver(port_path, @portname) do
            :ok -> :ok;
            {:error, :already_loaded} -> :ok;
            {:error, error_desc} -> 
                Logger.error("Cannot Load #{port_path} #{@portname} #{:erl_ddll.format_error(error_desc)}")
        end

        port = :erlang.open_port({:spawn, @portname}, [:binary])
        true = :erlang.register(@portname, port)
        state = %{port: port, waiters: []}
        response = :erlang.port_call(port, @cmd_init, "")
        Logger.debug("control init #{inspect(response)}")
        # response = :erlang.port_call(@portname, @cmd_open_client, "erlclient")
        # Logger.debug("control open_client #{inspect(response)}")
        
        {:ok, state}
    end

    # defp port_control(cmd, msg, state = %{port: port}) do
    #     port
    #     |> :erlang.port_control(cmd, msg)
    #     |> :erlang.binary_to_term()
    # end

    # def handle_call({:hello, msg}, from, state = %{port: port, waiters: waiters}) do
    #     #:erlang.port_command(port, msg)
    #     response = port_control(@cmd_echo, msg, state)
    #     Logger.debug("control #{inspect(response)}")
    #     {:noreply, %{state | waiters: waiters ++ [from] }}
    # end

    # def handle_info(:stop, state = %{port: port}) do
    #     :erlang.port_close(port)
    #     {:noreply, state}
    # end

    # def handle_info({port,{:data,data}}, state = %{port: port, waiters: [waiter | waiters]}) do
    #     Logger.debug("Data: #{inspect(data)}")
    #     GenServer.reply(waiter, data)
    #     state = handle_data(data, state)
    #     {:noreply, %{state | waiters: waiters} };
    # end

    # def handle_data(data, state) do
    #     state
    # end    
end