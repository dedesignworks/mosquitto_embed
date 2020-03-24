defmodule MosquittoEmbedTest do
  use ExUnit.Case
  doctest MosquittoEmbed

  test "greets the world" do
    assert MosquittoEmbed.hello() == :world
  end
end
