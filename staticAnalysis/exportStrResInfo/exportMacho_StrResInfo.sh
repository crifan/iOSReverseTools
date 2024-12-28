#!/bin/bash
# Function: Export/Extract single Mach-O file string and resources related info
# Author: Crifan Li
# Update: 20241228
# Refer: 
#  /Users/crifan/dev/dev_root/androidReverse/CloudPhone/Douyin/dy297/soLibs/common/exportElf_StrResInfo.sh
#  https://book.crifan.org/books/ios_re_static_analysis/website/analysis_content/export_str_res/common_suite/
# Usage:
#   chmod +x exportMacho_StrResInfo.sh
#   ./exportMacho_StrResInfo.sh input/dyld output

# SEPERATOR="--------------------"
SEPERATOR="===================="

# outpuFileSuffix="txt"
outpuFileSuffix="coffee"

function log() {
  echo "${SEPERATOR} $1 ${SEPERATOR}"
}

function extractInputFolder(){
  curInputFile=$1
  # echo "curInputFile=${curInputFile}"
  retInputFolder="$(dirname "${curInputFile}")"
  # echo "retInputFolder=${retInputFolder}"
  # return retInputFolder
  # return $retInputFolder
  # echo ${retInputFolder}
  echo $retInputFolder
}

function extractFilenameNoSuffix(){
  curInputFile=$1
  # echo "curInputFile=${curInputFile}"
  filenameWithSuffix="$(basename "${inputFile}")"
  # echo "filenameWithSuffix=${filenameWithSuffix}"
  filenameNoSuffix=${filenameWithSuffix%.*}
  # echo "filenameNoSuffix=${filenameNoSuffix}"
  echo ${filenameNoSuffix}
}

function initOutputFolerFromInputFolder(){
  inputFolder=$1
  # echo "inputFolder=${inputFolder}"
  outputFoler=$2
  # echo "outputFoler=${outputFoler}"
  if [ -z "$outputFoler" ]
  then
    if [ -z "$inputFolder" ]
    then
      outputFoler="."
    else
      outputFoler=${inputFolder}
    fi
    # echo "outputFoler=${outputFoler}"
    echo ${outputFoler}
  else
    echo ${outputFoler}
  fi
}

inputFile=$1
echo "inputFile=${inputFile}"
outputFoler=$2
echo "outputFoler=${outputFoler}"

# inputFolder="$(dirname "${inputFile}")"
inputFolder=$(extractInputFolder $inputFile)
echo "inputFolder=${inputFolder}"

inputMachoFile=$(extractFilenameNoSuffix $inputFile)
echo "inputMachoFile=${inputMachoFile}"
origgOutputMachoFile=${inputMachoFile}
echo "origgOutputMachoFile=${origgOutputMachoFile}"
outputMachoFile=${origgOutputMachoFile// /_}
outputMachoFile=${outputMachoFile//-/_}
echo "after remove special char: hyphen, space -> outputMachoFile=${outputMachoFile}"

# if [ -z "$outputFoler" ]
# then
#   if [ -z "$inputFolder" ]
#   then
#     outputFoler="."
#   else
#     outputFoler=${inputFolder}
#   fi
#   echo "outputFoler=${outputFoler}"
# fi

outputFoler=$(initOutputFolerFromInputFolder $inputFolder $outputFoler)
echo "outputFoler=${outputFoler}"

log "Exporting info use otool"
otool -l "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_otool_l.${outpuFileSuffix}
otool -oV "${inputFile}" > ${outputFoler}/""${outputMachoFile}""_otool_oV.${outpuFileSuffix}

log "Exporting info use nm"
nm "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_nm.${outpuFileSuffix}

log "Exporting info use strings"
strings "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_strings.${outpuFileSuffix}

log "Exporting info use jtool2"
export ARCH=arm64
jtool2 "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_strings.${outpuFileSuffix}

jtool2 -h "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_jtool2_h_header.${outpuFileSuffix}
jtool2 -l "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_jtool2_l_list.${outpuFileSuffix}
jtool2 -L "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_jtool2_L_library.${outpuFileSuffix}
jtool2 -S "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_jtool2_S_symbol.${outpuFileSuffix}

jtool2 --analyze "${inputFile}"
# outpu: dyld.ARM64.C21DBA37-9DF9-3FC7-B286-734030E18BB1

# findNameRegex="${outputMachoFile}".*.*
# findNameRegex="${inputFile}".*.*
findNameRegex="${inputMachoFile}".*.*
# findNameRegex="${origgOutputMachoFile}".*.*
echo "findNameRegex=${findNameRegex}"
# jtool2AnalyzeOutputFile="$(find . -maxdepth 1 -name ${findNameRegex} -printf 1 -quit)"
# jtool2AnalyzeOutputFile=$(find . -maxdepth 1 -name ${findNameRegex} -printf 1 -quit)
# jtool2AnalyzeOutputFile=$(find . -maxdepth 1 -name ${findNameRegex})
# jtool2AnalyzeOutputFile=$(find . -maxdepth 1 -name 'dyld.*')
# jtool2AnalyzeOutputFile=$(find . -maxdepth 1 -name ${findNameRegex} -printf 1)
# jtool2AnalyzeOutputFile=$(find . -name ${findNameRegex})
jtool2AnalyzeOutputFile=$(find . -maxdepth 1 -name ${findNameRegex})
echo "jtool2AnalyzeOutputFile=${jtool2AnalyzeOutputFile}"  # jtool2AnalyzeOutputFile=./dyld.ARM64.C21DBA37-9DF9-3FC7-B286-734030E18BB1
jtool2AnalyzeOutputFilename="$(basename "${jtool2AnalyzeOutputFile}")"
echo "jtool2AnalyzeOutputFilename=${jtool2AnalyzeOutputFilename}" # jtool2AnalyzeOutputFilename=dyld.ARM64.C21DBA37-9DF9-3FC7-B286-734030E18BB1
mv ${jtool2AnalyzeOutputFilename} ${outputFoler}/"${outputMachoFile}"_jtool2_analyze.${outpuFileSuffix}

log "Exporting info use rabin2"
rabin2 -I "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_I_identification.${outpuFileSuffix}
rabin2 -i "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_i_imports.${outpuFileSuffix}
rabin2 -E "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_E_exports.${outpuFileSuffix}
rabin2 -l "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_l_libraries.${outpuFileSuffix}
rabin2 -z "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_z_strings.${outpuFileSuffix}
rabin2 -s "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_s_symbols.${outpuFileSuffix}
rabin2 -S "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_rabin2_S_sections.${outpuFileSuffix}

log "Exporting entitlement info use ldid and codesign"
# export entitlements
ldid2 -e "${inputFile}" > ${outputFoler}/"${outputMachoFile}"_ldld_entitlement.xml
codesign -d --entitlements - "${inputFile}" &> ${outputFoler}/"${outputMachoFile}"_codesign_entitlement.xml

log "Exporting code sign info use codesign"
# export code sign info
#   for binary
codesign -vv -d "${inputFile}" &> ${outputFoler}/"${outputMachoFile}"_codesign.${outpuFileSuffix}
# #   for app
# codesign -vv -d xxx.App > iOSApp_codesign.txt

log "Exporting info Done"
