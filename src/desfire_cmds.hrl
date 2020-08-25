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

-record(desfire_cmd, {
    ins :: integer(),
    add_mac = false :: boolean(),
    reset_mac = false :: boolean(),
    tx = mac :: none | mac | encrypt,
    rx = mac :: none | mac | encrypt,
    expect_len = none :: integer() | none,
    header_len = 0,
    le = default :: integer() | none | default
}).

-define(PICC_AID, <<0,0,0>>).

-define(INS_SELECT_APP, 16#5A).
-define(INS_AUTHENTICATE_ISO, 16#1A).
-define(INS_AUTHENTICATE_AES, 16#AA).
-define(INS_GET_VERSION, 16#60).
-define(INS_CONTINUE, 16#AF).
-define(INS_GET_KEY_SETTINGS, 16#45).
-define(INS_GET_FILE_INFO, 16#F5).
-define(INS_READ_STD_FILE, 16#BD).
-define(INS_CHANGE_KEY, 16#C4).
-define(INS_CREATE_STD_FILE, 16#CD).
-define(INS_WRITE_STD_FILE, 16#3D).
-define(INS_CHANGE_FILE_SETTINGS, 16#5F).
-define(INS_FORMAT_PICC, 16#FC).
-define(INS_CREATE_APP, 16#CA).

-define(CMD_SELECT_APP, #desfire_cmd{
	ins = ?INS_SELECT_APP, tx = none, rx = none, reset_mac = true}).
-define(CMD_AUTHENTICATE_ISO, #desfire_cmd{
	ins = ?INS_AUTHENTICATE_ISO, tx = none, rx = none, reset_mac = true}).
-define(CMD_AUTHENTICATE_AES, #desfire_cmd{
	ins = ?INS_AUTHENTICATE_AES, tx = none, rx = none, reset_mac = true}).
-define(CMD_GET_VERSION, #desfire_cmd{ins = ?INS_GET_VERSION}).
-define(CMD_CONTINUE_AUTH, #desfire_cmd{
	ins = ?INS_CONTINUE, tx = none, rx = none, reset_mac = true}).
-define(CMD_CONTINUE_EMPTY, #desfire_cmd{ins = ?INS_CONTINUE, tx = none}).
-define(CMD_GET_KEY_SETTINGS, #desfire_cmd{ins = ?INS_GET_KEY_SETTINGS}).
-define(CMD_GET_FILE_INFO, #desfire_cmd{ins = ?INS_GET_FILE_INFO}).
-define(CMD_READ_STD_FILE, #desfire_cmd{
    ins = ?INS_READ_STD_FILE, rx = encrypt}).
-define(CMD_CHANGE_KEY, #desfire_cmd{ins = ?INS_CHANGE_KEY, tx = none}).
-define(CMD_CREATE_STD_FILE, #desfire_cmd{ins = ?INS_CREATE_STD_FILE}).
-define(CMD_WRITE_STD_FILE, #desfire_cmd{ins = ?INS_WRITE_STD_FILE,
    add_mac = true, tx = encrypt, header_len = 7}).
-define(CMD_CHANGE_FILE_SETTINGS, #desfire_cmd{ins = ?INS_CHANGE_FILE_SETTINGS,
    tx = encrypt, header_len = 1}).
-define(CMD_FORMAT_PICC, #desfire_cmd{ins = ?INS_FORMAT_PICC}).
-define(CMD_CREATE_APP, #desfire_cmd{ins = ?INS_CREATE_APP}).
