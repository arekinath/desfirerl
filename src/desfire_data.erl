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

-module(desfire_data).

-export([error_to_atom/1]).
-export([decode_picc_key_settings/1, decode_app_key_settings/1]).
-export([decode_version_info/1, encode_app_key_settings/1]).
-export([comm_settings_to_atom/1, comm_settings_from_atom/1]).
-export([decode_access/1, encode_access/1, decode_file_info/1]).

error_to_atom(16#00) -> ok;
error_to_atom(16#0c) -> no_changes;
error_to_atom(16#0e) -> out_of_eeprom;
error_to_atom(16#1c) -> bad_cmd;
error_to_atom(16#1e) -> integrity;
error_to_atom(16#40) -> no_key;
error_to_atom(16#7e) -> bad_length;
error_to_atom(16#9d) -> permission;
error_to_atom(16#9e) -> bad_parameter;
error_to_atom(16#a0) -> app_not_found;
error_to_atom(16#a1) -> app_integrity;
error_to_atom(16#ae) -> bad_auth;
error_to_atom(16#af) -> additional;
error_to_atom(16#be) -> boundary;
error_to_atom(16#c1) -> picc_integrity;
error_to_atom(16#ca) -> aborted;
error_to_atom(16#cd) -> picc_disabled;
error_to_atom(16#ce) -> out_of_apps;
error_to_atom(16#de) -> duplicate_app;
error_to_atom(16#ee) -> eeprom_failure;
error_to_atom(16#f0) -> not_found;
error_to_atom(16#f1) -> file_integrity;
error_to_atom(N) -> {unknown_error, N}.

comm_settings_to_atom(0) -> plain;
comm_settings_to_atom(1) -> mac;
comm_settings_to_atom(2) -> plain;
comm_settings_to_atom(3) -> encrypted.

comm_settings_from_atom(plain) -> 0;
comm_settings_from_atom(mac) -> 1;
comm_settings_from_atom(encrypted) -> 3.

encode_access(Access) ->
    RAccess = case Access of
        #{read := deny} -> 16#F;
        #{read := world} -> 16#E;
        #{read := {key, N}} -> N;
        _ -> 16#F
    end,
    WAccess = case Access of
        #{write := deny} -> 16#F;
        #{write := world} -> 16#E;
        #{write := {key, WN}} -> WN;
        _ -> 16#F
    end,
    RWAccess = case Access of
        #{readwrite := deny} -> 16#F;
        #{readwrite := world} -> 16#E;
        #{readwrite := {key, RWN}} -> RWN;
        _ -> 16#F
    end,
    AdmAccess = case Access of
        #{admin := deny} -> 16#F;
        #{admin := world} -> 16#E;
        #{admin := {key, AN}} -> AN;
        _ -> 16#F
    end,
    <<RWAccess:4, AdmAccess:4, RAccess:4, WAccess:4>>.

decode_access(Bin) ->
    <<RWAccess:4, AdmAccess:4, RAccess:4, WAccess:4>> = Bin,
    A0 = case RAccess of
        16#F -> #{read => deny};
        16#E -> #{read => world};
        N -> #{read => {key, N}}
    end,
    A1 = case WAccess of
        16#F -> A0#{write => deny};
        16#E -> A0#{write => world};
        WN -> A0#{write => {key, WN}}
    end,
    A2 = case RWAccess of
        16#F -> A1#{readwrite => deny};
        16#E -> A1#{readwrite => world};
        RWN -> A1#{readwrite => {key, RWN}}
    end,
    case AdmAccess of
        16#F -> A2#{admin => deny};
        16#E -> A2#{admin => world};
        AN -> A2#{admin => {key, AN}}
    end.

decode_file_info(Bin) ->
    <<Type, CommSettings, AccessBin:2/binary, FileInfoBin/binary>> = Bin,
    FileInfo0 = #{
        security => comm_settings_to_atom(CommSettings),
        access => decode_access(AccessBin)
    },
    case {Type, FileInfoBin} of
        {16#00, <<Size:24/little, _/binary>>} ->
            FileInfo0#{type => standard, size => Size};
        {16#01, <<Size:24/little, _/binary>>} ->
            FileInfo0#{type => backup, size => Size};
        {16#02, <<LowerLimit:32/little, UpperLimit:32/little, CredLimit:32/little, 1>>} ->
            FileInfo0#{type => value,
              range => {LowerLimit, UpperLimit},
              credit_limit => CredLimit};
        {16#02, <<LowerLimit:32/little, UpperLimit:32/little, _:32, 0>>} ->
            FileInfo0#{type => value,
              range => {LowerLimit, UpperLimit}};
        {16#03, <<RecSize:24/little, MaxRecords:24/little, CurrentRecords:24/little>>} ->
            FileInfo0#{type => linear_records,
              record_size => RecSize,
              max_records => MaxRecords,
              num_records => CurrentRecords};
        {16#04, <<RecSize:24/little, MaxRecords:24/little, CurrentRecords:24/little>>} ->
            FileInfo0#{type => cyclic_records,
              record_size => RecSize,
              max_records => MaxRecords,
              num_records => CurrentRecords}
    end.

decode_version_info(Bin) ->
    <<VendorId, Type, SubType, Major, Minor,
      StorSizeShift:7, _StorSizeBtw:1, Proto>> = Bin,
    StorSize = (1 bsl StorSizeShift),
    #{vendor => VendorId, type => {Type, SubType},
      version => {Major, Minor}, storage => StorSize,
      protocol => Proto}.

-spec decode_picc_key_settings(binary()) -> desfire:key_settings_picc().
decode_picc_key_settings(Bin) ->
    <<_:4, ConfigChange:1, ModWithoutMaster:1, GetWithoutMaster:1,
      MasterChange:1, KeyType:2, KeyNum:6>> = Bin,
    S0 = #{},
    S1 = case ConfigChange of
        0 -> S0#{key_settings => frozen};
        1 -> S0#{key_settings => changeable}
    end,
    S2 = case ModWithoutMaster of
        0 -> S1#{create_app => master};
        1 -> S1#{create_app => world}
    end,
    S3 = case GetWithoutMaster of
        0 -> S2#{get_apps => master};
        1 -> S2#{get_apps => world}
    end,
    S4 = case MasterChange of
        0 -> S3#{master_key => frozen};
        1 -> S3#{master_key => changeable}
    end,
    S5 = case KeyType of
        0 -> S4#{cipher => des_ecb};
        1 -> S4#{cipher => des3_ecb};
        2 -> S4#{cipher => aes_128_ecb}
    end,
    S5#{max_keys => KeyNum}.

-spec decode_app_key_settings(binary()) -> desfire:key_settings_app().
decode_app_key_settings(Bin) ->
    <<ChangeKey:4, ConfigChange:1, ModWithoutMaster:1, GetWithoutMaster:1,
      MasterChange:1, KeyType:2, KeyNum:6>> = Bin,
    S0 = case ChangeKey of
        16#0 -> #{change_key_mode => master};
        16#E -> #{change_key_mode => same_key};
        16#F -> #{change_key_mode => frozen};
        Other -> #{change_key_mode => {key, Other}}
    end,
    S1 = case ConfigChange of
        0 -> S0#{key_settings => frozen};
        1 -> S0#{key_settings => changeable}
    end,
    S2 = case ModWithoutMaster of
        0 -> S1#{create_delete_requires => master};
        1 -> S1#{create_delete_requires => any}
    end,
    S3 = case GetWithoutMaster of
        0 -> S2#{get_requires => master};
        1 -> S2#{get_requires => any}
    end,
    S4 = case MasterChange of
        0 -> S3#{master_key => frozen};
        1 -> S3#{master_key => changeable}
    end,
    S5 = case KeyType of
        0 -> S4#{cipher => des_ecb};
        1 -> S4#{cipher => des3_ecb};
        2 -> S4#{cipher => aes_128_ecb}
    end,
    S5#{max_keys => KeyNum}.

-spec encode_app_key_settings(desfire:key_settings_app()) -> binary().
encode_app_key_settings(Map) ->
    ChangeKey = case Map of
        #{change_key_mode := master} -> 16#0;
        #{change_key_mode := same_key} -> 16#E;
        #{change_key_mode := frozen} -> 16#F;
        #{change_key_mode := {key, Num}} when is_integer(Num) -> Num
    end,
    ConfigChange = case Map of
        #{key_settings := frozen} -> 0;
        #{key_settings := changeable} -> 1
    end,
    ModWithoutMaster = case Map of
        #{create_delete_requires := master} -> 0;
        #{create_delete_requires := any} -> 1
    end,
    GetWithoutMaster = case Map of
        #{get_requires := master} -> 0;
        #{get_requires := any} -> 1
    end,
    MasterChange = case Map of
        #{master_key := frozen} -> 0;
        #{master_key := changeable} -> 1
    end,
    KeyType = case Map of
        #{cipher := des_ecb} -> 0;
        #{cipher := des3_ecb} -> 1;
        #{cipher := aes_128_ecb} -> 2
    end,
    #{max_keys := KeyNum} = Map,
    <<ChangeKey:4, ConfigChange:1, ModWithoutMaster:1, GetWithoutMaster:1,
      MasterChange:1, KeyType:2, KeyNum:6>>.
