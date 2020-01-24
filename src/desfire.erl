%%
%% desfire host implementation
%%
%% Copyright 2020 Alex Wilson <alex@uq.edu.au>, The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-module(desfire).

-compile([{parse_transform, lager_transform}]).

-include_lib("pcsc/include/iso7816.hrl").

-behaviour(pcsc_apdu_transform).

-export([
    formats/0,
    init/1,
    begin_transaction/1,
    command/2,
    reply/2,
    end_transaction/1,
    terminate/1
]).

-export_type([command/0, reply/0, hwsw_version_info/0, version_info/0,
    cipher/0, key_settings/0, key_settings_picc/0, key_settings_app/0]).

-type command() ::
    select_cmd() | get_version_cmd() | get_key_settings_cmd() |
    authenticate_cmd() | get_file_info_cmd() | set_file_security_cmd() |
    read_std_file_cmd() | change_key_cmd() | change_file_settings_cmd() |
    write_std_file_cmd() | create_std_file_cmd() | format_card_cmd() |
    create_app_cmd().

-type reply() ::
    select_reply() | get_version_reply() | get_key_settings_reply() |
    authenticate_reply() | get_file_info_reply() | set_file_security_reply() |
    read_std_file_reply() | change_key_reply() | change_file_settings_reply() |
    write_std_file_reply() | create_std_file_reply() | format_card_reply() |
    create_app_reply().

-type aid() :: binary().
%% A DESfire AID (always 3 bytes in length).

-type select_cmd() :: {select_app, aid()}.
-type select_reply() :: ok | {error, term()}.

-type bytes() :: integer().
-type cipher() :: des_ecb | des3_ecb | aes_128_ecb.
-type keyid() :: integer().
-type fileid() :: integer().

-type key() :: binary().

-type hwsw_version_info() :: #{
    vendor => integer(),
    type => {Type :: integer(), SubType ::integer()},
    version => {Major :: integer(), Minor :: integer()},
    storage => bytes(),
    protocol => integer()
    }.
-type version_info() :: #{
    uid => binary(),
    batch => integer(),
    produced => {Year :: integer(), Week :: integer()},
    hwinfo => hwsw_version_info(),
    swinfo => hwsw_version_info()
    }.

-type get_version_cmd() :: get_version.
-type get_version_reply() :: {ok, version_info()} | {error, term()}.

-type key_settings() :: key_settings_picc() | key_settings_app().

-type key_settings_picc() :: #{
    cipher => cipher(),
    max_keys => integer(),
    key_settings => frozen | changeable,
    create_app => master | world,
    get_apps => master | world,
    master_key => frozen | changeable
    }.

-type key_settings_app() :: #{
    cipher => cipher(),
    max_keys => integer(),
    change_key_mode => master | same_key | frozen | {key, integer()},
    key_settings => frozen | changeable,
    create_delete_requires => master | any,
    get_requires => master | any,
    master_key => frozen | changeable
    }.

-type get_key_settings_cmd() :: get_key_settings.
-type get_key_settings_reply() :: {ok, key_settings()} | {error, term()}.

-type file_security() :: encrypted | plain | mac.

-type access_key_ref() :: {key, keyid()} | deny | world.

-type file_access() :: #{
    admin => access_key_ref(),
    read => access_key_ref(),
    readwrite => access_key_ref(),
    write => access_key_ref()
    }.

-type file_info_std() :: #{
    access => file_access(),
    security => file_security(),
    type => standard,
    size => bytes()
    }.
-type file_info_backup() :: #{
    access => file_access(),
    security => file_security(),
    type => backup,
    size => bytes()
    }.
-type file_info_value() :: #{
    access => file_access(),
    security => file_security(),
    type => value,
    range => {integer(), integer()},
    credit_limit => integer()
    }.
-type file_info_linear_records() :: #{
    access => file_access(),
    security => file_security(),
    type => linear_records,
    record_size => bytes(),
    max_records => integer(),
    num_records => integer()
    }.
-type file_info_cyclic_records() :: #{
    access => file_access(),
    security => file_security(),
    type => cyclic_records,
    record_size => bytes(),
    max_records => integer(),
    num_records => integer()
    }.

-type file_info() :: file_info_std() | file_info_backup() | file_info_value() |
    file_info_linear_records() | file_info_cyclic_records().

-type get_file_info_cmd() :: {get_file_info, fileid()}.
-type get_file_info_reply() :: {ok, file_info()} | {error, term()}.

-type authenticate_cmd() :: {authenticate, keyid(), cipher(), key()}.
-type authenticate_reply() :: ok | {error, term()}.

-type set_file_security_cmd() :: {set_file_security, fileid(), file_security()}.
-type set_file_security_reply() :: ok | {error, term()}.

-type read_std_file_cmd() :: {read_std_file, fileid(), Offset :: integer(),
    Length :: integer()}.
-type read_std_file_reply() :: {ok, binary()} | {error, term()}.

-type change_key_spec() :: #{
    cipher => cipher(),
    old_key => key(),
    new_key => key(),
    version => integer()
    }.

-type change_key_cmd() :: {change_key, keyid(), change_key_spec()}.
-type change_key_reply() :: ok | {error, term()}.

-type file_settings_spec() :: #{
    security => file_security(),
    access => file_access()
    }.

-type change_file_settings_cmd() :: {change_file_settings, fileid(),
    file_settings_spec()}.
-type change_file_settings_reply() :: ok | {error, term()}.

-type write_std_file_cmd() :: {write_std_file, fileid(), Offset :: integer(),
    Data :: binary()}.
-type write_std_file_reply() :: ok | {error, term()}.

-type std_file_spec() :: #{
    security => file_security(),
    access => file_access(),
    size => bytes()
    }.

-type create_std_file_cmd() :: {create_std_file, fileid(), std_file_spec()}.
-type create_std_file_reply() :: ok | {error, term()}.

-type format_card_cmd() :: format_card.
-type format_card_reply() :: ok | {error, term()}.

-type create_app_cmd() :: {create_app, aid(), key_settings_app()}.
-type create_app_reply() :: ok | {error, term()}.

-record(?MODULE, {
    fsm :: pid(),
    reqid :: gen_statem:request_id()
}).

%% @private
formats() -> {desfire, apdu}.

%% @private
init(_Proto) ->
    {ok, Pid} = desfire_proto:start_link(self(), self()),
    {ok, #?MODULE{fsm = Pid}}.

%% @private
terminate(#?MODULE{fsm = Pid}) ->
    process_flag(trap_exit, true),
    exit(Pid, shutdown),
    receive
        {'EXIT', Pid, _} -> ok
    end,
    process_flag(trap_exit, false),
    ok.

%% @private
begin_transaction(S = #?MODULE{}) ->
    {ok, S}.

%% @private
end_transaction(S = #?MODULE{}) ->
    {ok, S}.

command(V, S = #?MODULE{fsm = Pid}) ->
    ReqId = gen_statem:send_request(Pid, V),
    receive
        {apdu, Pid, A} ->
            {ok, [A], S#?MODULE{reqid = ReqId}}
    end.

reply(R, S = #?MODULE{fsm = Pid, reqid = ReqId}) ->
    Pid ! {apdu, self(), R},
    receive
        {apdu, Pid, A} ->
            {ok, [A], [], S};
        Msg ->
            case gen_statem:check_response(Msg, ReqId) of
                no_reply -> {error, {unknown_msg, Msg}};
                {reply, Ret} -> {ok, [Ret], S}
            end
    end.

