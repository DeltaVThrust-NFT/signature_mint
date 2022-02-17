require('dotenv').config()

const fs = require('fs')
const ethers = require('ethers')
const crypto = require('crypto')

try {
  const encryptedWalletJson = fs.readFileSync(
    './lib/signer.encrypted.json',
    'utf8',
  )

  const wallet = new ethers.Wallet.fromEncryptedJsonSync(
    encryptedWalletJson,
    process.env.SIGNER_PASSWORD,
  )

  console.log('Signer wallet decrypted:', wallet.address)

  const whitelistedAddress = process.argv[2]
  const salt = crypto.randomBytes(16).toString('base64')

  const payload = ethers.utils.defaultAbiCoder.encode(
    ['string', 'address', 'address'],
    [salt, process.env.CONTRACT_ADDRESS, whitelistedAddress],
  )

  let payloadHash = ethers.utils.keccak256(payload)

  wallet.signMessage(ethers.utils.arrayify(payloadHash)).then((token) => {
    console.table({
      allowedAddress: whitelistedAddress,
      salt,
      token,
    })
  })
} catch (err) {
  console.error(err)
}
