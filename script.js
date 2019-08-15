"use strict"
async function check_pubk() {
	const txt=document.getElementById('pubkey_amor').value
	if(!(txt.indexOf("-----END PGP PUBLIC KEY BLOCK-----") == -1))
		await get_pubkey_info();
	else
		document.getElementById('pubk_msginfo').innerText = "No valid public key found, or empty"
}
async function get_pubkey_info() {
	const pubkey 	= document.getElementById('pubkey_amor').value.trim()
	try {
	let str=""
	const publicKey 		= await openpgp.key.readArmored(pubkey)
	const publicKeyPacket = publicKey.keys[0].keyPacket
	const pubCreated 		= publicKeyPacket.created
	const pubFinger 		= publicKeyPacket.getFingerprint()
	const pubUser 		= publicKey.keys[0].users[0].userId.userid
	
	str += getListItem("User:",getEsceap(pubUser + " "+ strHash4String(strRight(pubFinger,16))+""))
	str += getListItem("Fingerprint",pubFinger)
	str += getListItem("Created",pubCreated)
	document.getElementById('info_pubkey').innerHTML = str
	document.getElementById('pubk_msginfo').innerHTML = ""
	}
	catch(e) {
		document.getElementById('info_pubkey').innerHTML = ""
		document.getElementById('pubk_msginfo').innerHTML = "No valid Public Key found: "+e
	}
}
async function verify() { await verify_helper() }
async function verify_helper(){
	try {	
 	const pgpPubKey 	= document.getElementById('pubkey_amor').value.trim()
	if(pgpPubKey=="") return 	
	const signMsg 	= document.getElementById('msgboxsigned').value.trim()
	let publicKeys = (await openpgp.key.readArmored(pgpPubKey)).keys
	const publicKeyPacket = publicKeys[0].keyPacket
	const pubFinger 		= publicKeyPacket.getFingerprint()
	const options = { message: await openpgp.cleartext.readArmored(signMsg), publicKeys: publicKeys }
	openpgp.verify(options).then((verified) => {
		const validity = verified.signatures[0].valid
		if (validity)
			document.getElementById('msg_verification').innerHTML = 
			  	getListItem("Message is valid",verified.signatures[0].valid)+
				getListItem("KeyId from Message",verified.signatures[0].keyid.toHex())+
				getListItem("KeyId from Public Key",strRight(pubFinger,16))
		else
			document.getElementById('msg_verification').innerHTML = 	
			  	getListItem("Message is valid","<span class=\"error\">"+verified.signatures[0].valid+"</span>")+
				getListItem("KeyId from Message",verified.signatures[0].keyid.toHex())+
				getListItem("KeyId from Public Key",strRight(pubFinger,16))	
	}).catch(err => {});
	} catch(e) {
		document.getElementById('info_pubkey').innerHTML = ""
		document.getElementById('msg_verification').innerHTML = "Verification error: "+e
	}
}
const strHash4String = (str) => { return "<span title=\""+str+"\">[" + str.substr(8, 4)+ "&nbsp;"+ str.substr(12, 4)+"]</span>" }
const getListItem = (strL, strR) => { return '<dt>'+strL+'</dt><dd>'+strR+'</dd>' }
const getEsceap = (str) => { return str.replace(">", "&gt;").replace("<", "&lt;") }
const strRight = (str,len) => { return str.substring(str.length-len, str.length) }		
let toID
const verify_delayed= function() {
	document.getElementById("msg_verification").innerText = "Verifying..."
	clearTimeout(toID)
	toID = setTimeout(verify, 250)
}