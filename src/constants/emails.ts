export const otpEmailFormat = (otpCode) => {
  return `
    Hi,
    To reset your password you otp is ${otpCode}
  `;
}