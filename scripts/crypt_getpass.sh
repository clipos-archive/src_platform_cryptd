#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2008-2018 ANSSI. All Rights Reserved.

function error() {
	logger -p daemon.err "crypt_getpass.sh: $1"
	exit 1
}

export DISPLAY=:0
if [[ -z "${UID}" ]]; then
	echo "uid no supplied" >&2
	exit 1
fi

HOME="$(awk -F: -vuid="${UID}" '{ if ($3 == uid) print $6 }' /etc/passwd)"
[[ -n "${HOME}" ]] || error "Unknown uid ${UID}"

AUTHORITY="/home/user/.Xauthority"
PINENTRY="vsctl user enter -u ${UID} -- /usr/local/bin/pinentry.sh ${AUTHORITY}"

ARG="${1}"
export LANG="fr_FR"
export LC_ALL="fr_FR"
TITLE="$(echo -e "${TITLE}" | sed -e 's/$/%%0A/g' | while read line; do echo -ne "$line"; done)"
TITLE="${TITLE%%\%\%0A}"
DEST="$(echo -e "${DEST}" | sed -e 's/$/%%0A/g' | while read line; do echo -ne "        $line"; done)"
case "${ARG}" in
	"encrypt")
		MSG="Veuillez saisir votre mot de passe pour le chiffrement de l'archive :%%0A        \"${TITLE}\""
		if [[ -n "${DEST}" ]]; then
			MSG="${MSG}%%0ADestinataires:%%0A${DEST}"
		else
			MSG="${MSG}%%0A(Pas de destinataires)"
		fi
		TYPE="passwd"
		TITLE="Mot de passe de chiffrement"
		;;
	"decrypt")
		MSG="Veuillez saisir votre mot passe pour le déchiffrement de l'archive :%%0A        \"${TITLE}\""
		TITLE="Mot de passe de déchiffrement"
		TYPE="passwd"
		;;
	"chpwold")
		MSG="Veuillez saisir l'ancien mot de passe de la clé privée :%%0A        \"${TITLE}\""
		TITLE="Ancien mot de passe"
		TYPE="passwd"
		;;
	"chpwnew")
		MSG="Veuillez saisir le nouveau mot de passe de la clé privée :%%0A        \"${TITLE}\""
		MSG2="Veuillez confirmer le nouveau mot de passe de la clé privée :%%0A        \"${TITLE}\""
		TITLE="Nouveau mot de passe"
		TITLE2="Confirmation du mot de passe"
		TYPE="double-passwd"
		;;
	"confirm")
		MSG="Confirmez-vous l'import du fichier suivant ?%%0A        \"${TITLE}\""
		TITLE="Confirmation d'un transfert montant"
		TYPE="confirm"
		;;
	"delete")
		MSG="Confirmez-vous la suppression de l'archive suivante ?%%0A        \"${TITLE}\""
		TITLE="Confirmation de suppression"
		TYPE="confirm"
		;;
	*)
		error "Unsupported argument : ${ARG}"
		;;
esac

BUTTONS="SETOK Confirmer\nSETCANCEL Annuler\n"
GETPASS="SETPROMPT Mot de passe :\nGETPIN\n"

case "${TYPE}" in
	double-passwd)
		PASS1="$(printf "SETTITLE ${TITLE}\n${BUTTONS}SETDESC ${MSG}\n${GETPASS}" | ${PINENTRY} 2>/dev/null | awk '$1 == "D" {print $2}')"
		[[ -n "${PASS1}" ]] || exit 1
		PASS2="$(printf "SETTITLE ${TITLE2}\n${BUTTONS}SETDESC ${MSG2}\n${GETPASS}" | ${PINENTRY} 2>/dev/null | awk '$1 == "D" {print $2}')"
		if [[ "${PASS1}" != "${PASS2}" ]]; then
			printf "SETTITLE Saisie incorrecte\nSETDESC Les deux saisies ne correspondent pas.\nSETOK Annuler\nMESSAGE\n" | ${PINENTRY} 2>/dev/null
			exit 1
		fi
		echo "${PASS1}" | sed -e 's/%25/%/g'
		exit 0
		;;
	passwd)
		PASS="$(printf "SETTITLE ${TITLE}\nSETOK Confirmer\nSETCANCEL Annuler\nSETDESC ${MSG}\n${GETPASS}" | ${PINENTRY} 2>/dev/null | awk '$1 == "D" {print $2}')"
		echo "${PASS}" | sed -e 's/%25/%/g'
		exit 0
		;;
	confirm)
		ERR=$(printf "SETTITLE ${TITLE}\nSETDESC ${MSG}\nSETOK Confirmer\nSETCANCEL Annuler\nCONFIRM\n" | ${PINENTRY} 2>/dev/null | grep ERR)
		[[ -n "${ERR}" ]] && exit 1
		exit 0
		;;
esac
