package keystore

import (
	"errors"
)

var ERROR_wallet_password_fail = errors.New("wallet password fail")                 //钱包密码错误
var ERROR_netAddr_password_fail = errors.New("net address password fail")           //网络地址密码错误
var ERROR_wallet_address_password_fail = errors.New("wallet address password fail") //钱包地址密码错误
var ERROR_DHKey_password_fail = errors.New("DHKey password fail")                   //DHKey密码错误
var ERROR_address_empty = errors.New("address empty")                               //地址为空
var ERROR_get_address_info_errer = errors.New("get address info errer")             //获取地址信息错误
var ERROR_get_dhkey_errer = errors.New("get DHKey errer")                           //获取DHKey错误
var ERROR_get_netaddr_errer = errors.New("get NetAddr errer")                       //获取网络地址错误
var ERROR_netaddr_empty = errors.New("get NetAddr empty")                           //网络地址为空
