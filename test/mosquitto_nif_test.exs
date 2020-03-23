defmodule MosquittoNifTest do
  use ExUnit.Case
  doctest MosquittoNif

  test "greets the world" do
    assert MosquittoNif.hello() == :world
  end
end
