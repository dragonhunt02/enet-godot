-module(enet_pool).
-behaviour(gen_server).

%% API
-export([
    start_link/2,
    add_peer/3,
    pick_peer/3,
    remove_peer/3, 
    connect_peer/3,
    disconnect_peer/3,
    connect_peer/2,
    disconnect_peer/2,
    worker_id/2,
    active_peers/1,
    worker_id/3
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2
]).

-record(state, {
    port
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Port, PeerLimit) ->
    gen_server:start_link(?MODULE, [Port, PeerLimit], []).

add_peer(Port, Socket, Name) ->
    gproc_pool:add_worker(Port, {Socket, Name}).

pick_peer(Port, Socket, PeerID) ->
    gproc_pool:pick_worker(Port, {Socket, PeerID}).

remove_peer(Port, Socket, Name) ->
    gproc_pool:remove_worker(Port, {Socket, Name}).

connect_peer(Port, Socket, Name) ->
    gproc_pool:connect_worker(Port, {Socket, Name}).

disconnect_peer(Port, Socket, Name) ->
    gproc_pool:disconnect_worker(Port, {Socket, Name}).

connect_peer(Port, Name) ->
    gproc_pool:connect_worker(Port, Name).
disconnect_peer(Port, Name) ->
    gproc_pool:disconnect_worker(Port, Name).
worker_id(Port, Name) ->
    gproc_pool:worker_id(Port, Name).

active_peers(Port) ->
    gproc_pool:active_workers(Port).

worker_id(Port, Socket, Name) ->
    gproc_pool:worker_id(Port, {Socket, Name}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Port, PeerLimit]) ->
    process_flag(trap_exit, true),
    true = gproc:reg({n, l, {enet_pool, Port}}),
    try gproc_pool:new(Port, direct, [{size, PeerLimit}, {auto_size, false}]) of
        ok -> ok
    catch
        error:exists -> ok
    end,
    {ok, #state{port = Port}}.

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{port = Port}) ->
    gproc_pool:force_delete(Port),
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================
