export interface AuthRepository<TFile = unknown> {
    findCredentialById(
        id: string,
    ): Promise<{ id: string; password: string; userId: string } | undefined>;

    createCredential(params: {
        id: string;
        password: string;
        userId: string;
    }): Promise<void>;

    updatePassword(id: string, hashedPassword: string): Promise<void>;

    findUserById(userId: string): Promise<
        | {
              id: string;
              role: string;
              name: string;
          }
        | undefined
    >;

    createUser(userData: {
        id: string;
        role: string;
        name?: string;
        email?: string;
        profileImage?: TFile;
    }): Promise<{
        id: string;
        role: string;
        name: string;
    }>;

    findThirdPartyAuth(
        provider: string,
        providerId: string,
    ): Promise<{ userId: string } | undefined>;

    createThirdPartyAuth(params: {
        id: string;
        provider: string;
        userId: string;
    }): Promise<void>;
}
