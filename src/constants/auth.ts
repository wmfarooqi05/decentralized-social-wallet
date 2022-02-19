export const USERNAME_LENGTH = {
    min: 4,
    max: 20,
}

export const USERNAME_REGEX = /^(?=.{4,20}$)(?![0-9_.])(?!.*[_.]{2})[a-zA-Z0-9._]+(?<![_.])$/;