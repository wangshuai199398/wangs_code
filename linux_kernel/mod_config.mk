#driver sub-module config
CONFIG_YSMOD_NP := n
CONFIG_YSMOD_MAC := n
CONFIG_YSMOD_LAN := n
CONFIG_YSMOD_CDEV := n
#only enable one hw
CONFIG_YSHW_SEC := n
CONFIG_YSHW_SWIFTN := n
CONFIG_YSHW_2100P := n
CONFIG_YSHW_K2PRO := n
CONFIG_YSHW_K2 := n
CONFIG_YSHW_LDMA3 := n
CONFIG_YSHW_K2ULTRA := m
CONFIG_YSHW_KMACHINE := n
#Decide whether to split into double driver for compilation 
CONFIG_YSARCH_PLAT := n
