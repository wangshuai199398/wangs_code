#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

declare config_ysarch_plat=n

declare -A hw_module_map=(
    ["K2"]="cdev:y mac:c lan:k np:k"
    ["K2PRO"]="cdev:y mac:u lan:k np:k"
    ["K2ULTRA"]="cdev:y mac:x lan:k2u np:k2u"
    ["K2ULTRA_U200"]="cdev:y mac:x lan:k2u np:k2u"
    ["K2ULTRA_CS"]="cdev:y mac:x lan:k2u np:n"
    ["2100P"]="cdev:y mac:x lan:k np:k"
    ["SWIFTN"]="cdev:y mac:l2 lan:n np:n"
    ["LDMA3"]="cdev:y mac:l3 lan:e np:n"
    ["SEC"]="cdev:y mac:n lan:n np:n"
    ["KMACHINE"]="cdev:y mac:n lan:n np:n"
)

# Map full hardware name to the single letter choice
declare -A hw_choice_map=(
    ["K2"]="K"
    ["K2PRO"]="K2P"
    ["K2ULTRA"]="K2U"
    ["K2ULTRA_U200"]="K2U_U200"
    ["K2ULTRA_CS"]="K2UC"
    ["2100P"]="P"
    ["SWIFTN"]="S"
    ["LDMA3"]="L"
    ["SEC"]="SEC"
    ["KMACHINE"]="KM"
)

# Initialize hw_map
declare -A hw_map
for key in "${!hw_module_map[@]}"; do
    hw_map[$key]=n
done

read_hw_choice() {
    local keys=("${!hw_module_map[@]}")
    local hw_choices=$(printf "/%s" "${keys[@]}")
    hw_choices=${hw_choices:1}
    read -p "Enable ${hw_choices} hardware? " hw_choice
    hw_choice=${hw_choice^^}
    hw_choice_key=""
    for key in "${!hw_choice_map[@]}"; do
        if [[ "${hw_choice_map[$key]}" == "$hw_choice" ]]; then
            hw_choice_key=$key
            break
        fi
    done
    if [[ -z "$hw_choice_key" ]]; then
        echo "Invalid input, please enter one of the following: ${hw_choices}."
        exit 1
    fi
    echo "$hw_choice_key"
}

expert_mode() {
    local module_keys=("cdev" "mac" "lan" "np")
    declare -A module_map_selected
    for mod in "${module_keys[@]}"; do
        while true; do
            read -p "Enable ${mod}? (y/n): " choice
            if [[ "$choice" == "y" || "$choice" == "n" ]]; then
                module_map_selected[$mod]=$choice
                break
            else
                echo "Invalid input. Please enter 'y' or 'n'."
            fi
        done
    done

    while true; do
        read -p "Configure double driver compilation? (y/n): " plat_choice
        if [[ "$plat_choice" == "y" || "$plat_choice" == "n" ]]; then
            config_ysarch_plat=$plat_choice
            break
        else
            echo "Invalid input. Please enter 'y' or 'n'."
        fi
    done

    echo "#driver sub-module config" > mod_config.mk
    for mod in ${!module_map_selected[@]}; do
        echo "CONFIG_YSMOD_${mod^^} := ${module_map_selected[$mod]}" >> mod_config.mk
    done

    while true; do
        hw_choice=$(read_hw_choice)
        if [[ -z "${hw_map[$hw_choice]}" ]]; then
            echo "Invalid hardware choice, please choose again."
        else
            hw_map[$hw_choice]=y
            break
        fi
    done

    echo "#only enable one hw" >> mod_config.mk
    for key in ${!hw_map[@]}; do
        if [[ ! -z "${hw_module_map[$key]}" ]]; then
            if [[ "${hw_map[$key]}" == "y" ]]; then
                echo "CONFIG_YSHW_${key} := m" >> mod_config.mk
            else
                echo "CONFIG_YSHW_${key} := ${hw_map[$key]}" >> mod_config.mk
            fi
        else
            echo "Error: Invalid hardware key ${key}. Exiting."
            exit 1
        fi
    done

    echo "#Decide whether to split into double driver for compilation " >> mod_config.mk
    echo "CONFIG_YSARCH_PLAT := $config_ysarch_plat" >> mod_config.mk

    echo "make config done!"
    exit 0
}

if [[ $1 == "expert" ]]; then
    expert_mode
fi

if [[ -z $1 ]]; then
    hw_choice=$(read_hw_choice)
else
    hw_choice_arg=${1^^}
    hw_choice=""
    for key in "${!hw_choice_map[@]}"; do
        if [[ "${hw_choice_map[$key]}" == "$hw_choice_arg" ]]; then
            hw_choice=$key
            break
        fi
    done
    if [[ -z "$hw_choice" ]]; then
        echo "Invalid input, please enter one of the following: ${!hw_choice_map[@]}."
        exit 1
    fi

    if [[ $2 == "double" ]]; then
        echo "will generate double driver for compilation"
        config_ysarch_plat=y
    fi
fi

if [ -z "${hw_map[$hw_choice]}" ]; then
    echo "Invalid hardware choice. Exiting."
    exit 1
fi

hw_map[$hw_choice]=y

# Parse module configuration for the selected hardware
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
