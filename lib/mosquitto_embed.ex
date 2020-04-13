defmodule MosquittoEmbed do

    defdelegate subscribe(topic, user_data), to: MosquittoEmbed.Driver
    defdelegate unsubscribe(topic), to: MosquittoEmbed.Driver
    defdelegate publish(topic, payload, retain \\ false, qos \\ 0), to: MosquittoEmbed.Driver
end
