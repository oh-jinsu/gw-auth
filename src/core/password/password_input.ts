/** Password credentials accepted by both browser and mobile login. */
export type PasswordLoginInput = {
  id: string;
  password: string;
};

/** Input accepted by the password-account signup use case. */
export type PasswordSignupInput<TRegistrationInput> = {
  id: string;
  password: string;
  passwordConfirm: string;
  registration: TRegistrationInput;
};
