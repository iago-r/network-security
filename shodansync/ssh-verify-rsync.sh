# shellcheck shell=bash
datestr=$(date +%s)
echo "$datestr cmd=$SSH_ORIGINAL_COMMAND" >> "$HOME/.ssh/ssh-verify-rsync.log"
if echo "$SSH_ORIGINAL_COMMAND" | grep -qE '[&;<>`|]'; then
  echo Rejected
elif [[ "${SSH_ORIGINAL_COMMAND:0:14}" == "rsync --server" ]]; then
  $SSH_ORIGINAL_COMMAND
else
  echo Rejected
fi
