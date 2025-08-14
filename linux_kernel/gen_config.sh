#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

declare config_ysarch_plat=n

declare -A hw_module_map=(
    ["K2ULTRA"]="cdev:y mac:x lan:k2u np:k2u"
)

declare -A hw_choice_map=(
    ["K2ULTRA"]="K2U"
)

declare -A hw_map
for key in "${!hw_module_map[@]}"; do
    hw_map[$key]=n
done

hw_choice_arg=${1^^}
hw_choice=""
for key in "${!hw_choice_map[@]}"; do
    if [[ "${hw_choice_map[$key]}" == "$hw_choice_arg" ]]; then
        hw_choice=$key
        break
    fi
done

hw_map[$hw_choice]=y

IFS=' ' read -r -a mod_config <<< "${hw_module_map[$hw_choice]}"
declare -A module_map_selected
for mod in "${mod_config[@]}"; do
    IFS=':' read -r key value <<< "$mod"
    module_map_selected[$key]=$value
done

echo "#driver sub-module config" > mod_config.mk
for mod in ${!module_map_selected[@]}; do
    echo "CONFIG_YSMOD_${mod^^} := ${module_map_selected[$mod]}" >> mod_config.mk
done

echo "#only enable one hw" >> mod_config.mk
for key in ${!hw_map[@]}; do
    if [[ "${hw_map[$key]}" == "y" ]]; then
        echo "CONFIG_YSHW_${key} := m" >> mod_config.mk
    else
        echo "CONFIG_YSHW_${key} := ${hw_map[$key]}" >> mod_config.mk
    fi
done

echo "#Decide whether to split into double driver for compilation " >> mod_config.mk
echo "CONFIG_YSARCH_PLAT := $config_ysarch_plat" >> mod_config.mk

echo "make config done!"
