# SPDX-License-Identifier: 0BSD
$0 ~ /^Signed-off-by: [^<>]+ <[A-Za-z0-9!#$%&'*+\/?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+\/?^_`{|}~-]+)*@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?>$/ {
  address = $0
  sub(/^.* </, "", address)
  sub(/>$/, "", address)
  if (tolower(address) == tolower(ENVIRON["AUTHOR_EMAIL"])) matched = 1
}
END { exit matched ? 0 : 1 }
