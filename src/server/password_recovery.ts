import type { AuthRepository } from "./auth_repository";
import type { JWTManager } from "./jwt_manager";
import nodemailer from "nodemailer";
import bcrypt from "bcryptjs";
import { exception, ok, resultFrom } from "gw-result";

export class PasswordRecoveryService {
  siteOrigin: string;
  siteName: string;
  passwordRecoveryTokenManager: JWTManager;
  authRepository: AuthRepository;
  emailCredentials: {
    service: string;
    user: string;
    pass: string;
  };

  constructor({
    siteOrigin,
    siteName,
    authRepository,
    emailCredentials,
    passwordRecoveryTokenManager,
  }: {
    siteOrigin: string;
    siteName: string;
    authRepository: AuthRepository;
    emailCredentials: {
      service: string;
      user: string;
      pass: string;
    };
    passwordRecoveryTokenManager: JWTManager;
  }) {
    this.siteOrigin = siteOrigin;
    this.siteName = siteName;
    this.passwordRecoveryTokenManager = passwordRecoveryTokenManager;
    this.authRepository = authRepository;
    this.emailCredentials = emailCredentials;
  }

  async requestPasswordReset(email: string) {
    const credential = await this.authRepository.findCredentialById(email);

    if (!credential) {
      return exception("CREDENTIAL_NOT_FOUND", "계정이 존재하지 않습니다.");
    }

    const transporter = nodemailer.createTransport({
      service: this.emailCredentials.service,
      auth: {
        user: this.emailCredentials.user,
        pass: this.emailCredentials.pass,
      },
    });

    const tokenResult = await this.passwordRecoveryTokenManager.sign({
      id: credential.id,
    });

    if (tokenResult.isErr) {
      return tokenResult;
    }

    const token = tokenResult.value;

    const link = `${this.siteOrigin}/reset-password?token=${token}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: `${this.siteName} 비밀번호 재설정`,
      html: `<main>
        <p>비밀번호 재설정을 위해 아래 링크를 클릭해 주세요. 링크는 한 시간 동안 유효합니다. 다른 사람에게 공유하지 마세요.</p>
        <a href="${link}" target="_blank">${link}</a>
    </main>`,
    } satisfies nodemailer.SendMailOptions;

    const result = await resultFrom(() => transporter.sendMail(mailOptions));

    return result;
  }

  async resetPassword(
    token: string,
    password: string,
    passwordConfirm: string,
  ) {
    const verifyResult = await this.passwordRecoveryTokenManager.verify(token);

    if (verifyResult.isErr) {
      return verifyResult;
    }

    const payload = verifyResult.value;

    if (typeof payload.id !== "string") {
      return exception("INVALID_TOKEN", "토큰이 유효하지 않습니다.");
    }

    const credential = await this.authRepository.findCredentialById(payload.id);

    if (!credential) {
      return exception("CREDENTIAL_NOT_FOUND", "계정이 존재하지 않습니다.");
    }

    if (typeof password !== "string" || !password.trim()) {
      return exception("INVALID_PASSWORD", "비밀번호가 유효하지 않습니다.");
    }

    if (password !== passwordConfirm) {
      return exception("PASSWORD_MISMATCH", "비밀번호가 일치하지 않습니다.");
    }

    const updatePasswordResult = await resultFrom(() =>
      this.authRepository.updatePassword(
        credential.id,
        bcrypt.hashSync(password, 10),
      ),
    );

    if (updatePasswordResult.isErr) {
      return updatePasswordResult;
    }

    return ok();
  }
}
