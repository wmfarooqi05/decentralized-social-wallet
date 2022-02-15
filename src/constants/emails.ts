export const otpEmailFormat = (otpCode) => {
  return `
    Hi,
    To reset your password you otp is ${otpCode}
  `;
};

export const newAccountOtpEmailFormat = (otpCode) => {
  return `
    Hi,
    To finish your signup you otp is ${otpCode}
  `;
};


export const otpPhoneFormat = (otpCode) => {
  return `
    Hi,
    To reset your password you otp is ${otpCode}
  `;
};

export const NEW_ACCOUNT_SMS = (otpCode) => {
  return `
    Hi,
    To finish your signup you otp is ${otpCode}
  `;
};

export const NEW_ACCOUNT_EMAIL = 'NEW_ACCOUNT_EMAIL';

export const FORGOT_PASSWORD_HEADING = 'Forgot Password';
