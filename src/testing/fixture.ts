/** Repository plus optional cleanup used by one isolated conformance run. */
export type RepositoryConformanceFixture<TRepository> = {
  /** Empty repository namespace used only by the current assertion run. */
  repository: TRepository;

  /** Releases connections or deletes fixture records after every outcome. */
  dispose?(): void | Promise<void>;
};

/** Creates one empty, isolated repository fixture for a conformance assertion. */
export type RepositoryConformanceFactory<TFixture> = () => TFixture | Promise<TFixture>;

/** Runs an assertion and always disposes its isolated repository fixture. */
export async function withRepositoryFixture<
  TFixture extends RepositoryConformanceFixture<unknown>,
>(
  factory: RepositoryConformanceFactory<TFixture>,
  assertion: (fixture: TFixture) => Promise<void>,
) {
  const fixture = await factory();

  try {
    await assertion(fixture);
  } finally {
    await fixture.dispose?.();
  }
}
