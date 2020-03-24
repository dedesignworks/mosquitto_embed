defmodule MosquittoEmbed.Driver do
    use GenServer
    require Logger


    @portname 'mosquitto_embed'

    def start_link(args \\ []) do
        GenServer.start_link(__MODULE__, args)
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
        state = %{port: port}
        {:ok, state}
    end

    def handle_info(stop, state = %{port: port}) do
        :erlang.port_close(port)
        {:noreply, state}
    end

    def handle_info({port,{:data,data}}, state = %{port: port}) do
        Logger.debug("Data: #{inspect(data)}")
        state = handle_data(data, state)
        {:noreply, state};
    end


    def handle_data(data, state) do
        state
    end    
end