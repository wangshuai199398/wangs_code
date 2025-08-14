#!/bin/sh
DEFERRED=42
deferred_pos=
deferred_neg=
auto_cfg_file=compat_config.h
KPATH=$1
SYMBFPATH=$2

echo "kernel path ${KPATH}"
echo "start checking kernel compat..."
if [ -e ${auto_cfg_file} ]; then
   echo "${auto_cfg_file} has existed."
   exit 1
fi

#移除所有的多行注释和所有包含 #include 的行
function strip_comments()
{
    local file=$1

    cat $1 | sed -e '
/\/\*/!b
:a
/\*\//!{
N
ba
}
s:/\*.*\*/::' | sed -e '/^#include/d'
}

# 生成 deferred_pos
# pos "***"
function defer_test_compile()
{
    local sense=$1
    local source="$2"
    echo "$source" > "$compile_dir/test_$key.c"
    echo "obj-m += test_$key.o" >> "$compile_dir/Makefile"
    eval deferred_$sense=\"\$deferred_$sense $key\"
    return $DEFERRED
}

# 判断头文件中有没有个该符号的定义
# test_symbol DEVLINK_PARAM_DRIVER include/net/devlink.h
function test_symbol()
{
    local symbol=$1
    shift
    local file
    local prefix
    local prefix_list

    for file in "$@"; do
        # For speed, lets just grep through the file. The symbol may
        # be of any of these forms:
        #     #define SYMBOL
        #     typedef void (SYMBOL)(void)
        #     extern void SYMBOL(void)
        #     void (*SYMBOL)(void)
        #     enum { SYMBOL, } void
        #
        # Since 3.7 headers can be in both $KPATH/include
        #     or $KPATH/include/uapi so check both
        # If the file contains "include/linux" then build set of
        # prefixes

        prefix=$(dirname $file)
        file=$(basename $file)
        if [ "$prefix" == "include/linux/" ]; then
            prefix_list="include/linux/ include/uapi/linux/"
        else
            prefix_list="$prefix/"
        fi

        for prefix in $prefix_list; do
		[ -f "$KPATH/$prefix$file" ] &&  \
			strip_comments $KPATH/$prefix$file | \
			egrep -w "$symbol" >/dev/null && \
			return 0
        done
    done
    return 1
}

# pos netif_napi_add include/linux/netdevice.h void (struct net_device *, struct napi_struct *, int (*)(struct napi_struct *, int), int)
function defer_test_symtype()
{
    local sense=$1
    local symbol=$2
    local file=$3
    shift 3
    local type="$*"

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi
    defer_test_compile $sense "
#include <linux/types.h>
#include <${file:8}>


__typeof($type) *kernel_compat_dummy = &$symbol;
"
}


function defer_test_memtype()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4
    local memtype="$*"

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_symtype() can work in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
__typeof($memtype) *kernel_compat_dummy_2 = &kernel_compat_dummy_1.$memname;
"
}

function defer_test_bitfield()
{
    local sense=$1
    local aggtype="${2/_/ }"
    local memname=$3
    local file=$4
    shift 4

    if [ ${file:0:8} != "include/" ]; then
        fail "defer_test_bitfield() only works in include/ - request was '$file'"
    fi

    defer_test_compile $sense "
#include <${file:8}>
$aggtype kernel_compat_dummy_1;
unsigned long test(void) {
        return kernel_compat_dummy_1.$memname;
}
"
}

# do_symbol do_symtype do_member do_memtype do_file

function do_symbol()  { shift 2; test_symbol "$@"; }
function do_nsymbol() { shift 2; ! test_symbol "$@"; }
function do_symtype() { shift 2; defer_test_symtype pos "$@"; }
function do_nsymtype() { shift 2; defer_test_symtype neg "$@"; }
function do_member() { shift 2; defer_test_memtype pos "$@" void; }
function do_nmember() { shift 2; defer_test_memtype neg "$@" void; }
function do_memtype() { shift 2; defer_test_memtype pos "$@"; }
function do_nmemtype() { shift 2; defer_test_memtype neg "$@"; }
function do_bitfield() { shift 2; defer_test_bitfield pos "$@"; }
function do_nbitfield() { shift 2; defer_test_bitfield neg "$@"; }
function do_export()
{
    local sym=$3
    shift 3

    # Only scan header files for the symbol
    test_symbol $sym $(echo "$@" | sed -r 's/ [^ ]+\.c/ /g') || return
    test_export $sym "$@"
}
function do_nexport() { ! do_export "$@"; }

# 直接判断文件是否存在
function do_file()
{
    for file in "$@"; do
        if [ -f $KPATH/$file ]; then
            return 0
        fi
    done
    return 1
}
function do_nfile()   { ! do_file "$@"; }

function do_custom()  { do_$1; }

function do_EFX_NEED_TIMESPEC64_TO_NS_SIGNED()
{
        test -f $KPATH/include/linux/time64.h &&
        grep -q 'Prevent multiplication overflow ./' $KPATH/include/linux/time64.h
}


# cat ./kernel_compat/symbolsfile | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
# 去除所有注释和空白行，然后将所有剩余行中的连续空白字符替换为单个冒号
kompat_symbols="$(cat $SYMBFPATH | egrep -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g')"

#创建一个临时目录
compile_dir="$(mktemp -d)"
rmfiles="$rmfiles $compile_dir"

#在临时目录中创建Makefile文件,并将$makefile_prefix写入
echo >"$compile_dir/Makefile" "$makefile_prefix"
echo "ccflags-y += -Wall -Werror" >> "$compile_dir/Makefile"
deferred_pos=
deferred_neg=

cat /dev/null > $auto_cfg_file
echo "/* SPDX-License-Identifier: GPL-2.0 */"  >> "$auto_cfg_file"

# Note that for deferred tests this runs after the Makefile has run all tests
function do_one_symbol() {
    local key=$1
    shift
    # do_symbol do_symtype do_member do_memtype do_file
    if "$@"; then
        echo "#define $key yes" >> "$auto_cfg_file"
	elif [ $? -ne $DEFERRED ]; then
        echo "// #define $key" >> "$auto_cfg_file"
    fi
}

# 
for symbol in $kompat_symbols; do
    set -o noglob
    IFS=:
    set -- $symbol
    unset IFS
    set +o noglob

    key="$1"       #macro
    method="$2"    #type
    do_one_symbol $key do_${method} "$@"
done

# eval make -C /lib/modules/$(uname -r)/build -k O="" M="/tmp/tmp.CrT8PNcuiS" >"/tmp/tmp.CrT8PNcuiS/log" 2>&1 || true
# 在 /lib/modules/$(uname -r)/build 下使用 Makefile 构建代码，并将输出信息记录到 $compile_dir/log 文件中。即使错误，整个命令也不会导致脚本停止运行
eval make -C $KPATH -k $EXTRA_MAKEFLAGS O="$KOUT" M="$compile_dir" >"$compile_dir/log" 2>&1 || true

# 是否存在 .o 文件
for key in $deferred_pos; do
    # 只要生成了目标文件（.o 文件），就认为编译过程没有出现警告或错误
    do_one_symbol $key test -f "$compile_dir/test_$key.o"
done

# 没有
for key in $deferred_neg; do
    do_one_symbol $key test ! -f "$compile_dir/test_$key.o"
done

rm -rf $rmfiles
echo "finished checking kernel compat."
