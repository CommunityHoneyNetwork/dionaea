#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o errexit
set -o nounset
set -o pipefail


main() {

  local dionaea_log_level=info

  if [[ ${DEBUG} == "true" ]]
  then
    set -o xtrace
    dionaea_log_level=debug
  fi

  local deploy_key=${DEPLOY_KEY:-}
  local chn_server=${CHN_SERVER}
  local json=${DIONAEA_JSON:-dionaea.json}
  local ip=${IP_ADDRESS:-}

  local debug=${DEBUG:-false}

  mkdir -p `dirname ${DIONAEA_JSON}`

  if [[ -z ${DEPLOY_KEY} ]]
  then
    echo "[CRIT] - No deploy key found"
    sleep 10
    exit 1
  fi

  chn-register.py \
        -k \
        -p dionaea \
        -d "${deploy_key}" \
        -u "${chn_server}" \
        -o "${json}" \
        -i "${ip}"

  export IDENT="$(cat ${json} | jq -r .identifier)"
  export SECRET="$(cat ${json} | jq -r .secret)"

  python3 /opt/scripts/build_config.py
  if [[ $? -ne 0 ]]
  then
      echo "Config build failed; verify config and then restart the container."
      sleep 120
      exit 1
  fi

  exec /opt/dionaea/bin/dionaea -c "/opt/dionaea/etc/dionaea/dionaea.cfg" -u dionaea -g nogroup -l ${dionaea_log_level}
  sleep 10
}


main "$@"
