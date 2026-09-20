export const PASSWORD_GENERATOR_DEFAULT_LENGTH = 16;
export const PASSWORD_GENERATOR_MIN_LENGTH = 8;
export const PASSWORD_GENERATOR_MAX_LENGTH = 32;

export const PASSWORD_CHARACTER_SETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  numbers: '0123456789',
  symbols: '!@#$%^&*()_+[]{}|;:,.<>?/~`-=',
} as const;

export type PasswordCharacterOption = keyof typeof PASSWORD_CHARACTER_SETS;
export type PasswordCharacterSelection = Record<PasswordCharacterOption, boolean>;

export const DEFAULT_PASSWORD_CHARACTER_SELECTION: PasswordCharacterSelection = {
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

function secureRandomIndex(maxExclusive: number) {
  if (maxExclusive <= 0) throw new Error('El conjunto de caracteres está vacío');

  const randomValues = new Uint32Array(1);
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  do {
    window.crypto.getRandomValues(randomValues);
  } while (randomValues[0] >= limit);
  return randomValues[0] % maxExclusive;
}

export function generateSecurePassword(
  length: number,
  selection: PasswordCharacterSelection,
) {
  const selectedSets = (Object.keys(PASSWORD_CHARACTER_SETS) as PasswordCharacterOption[])
    .filter((option) => selection[option])
    .map((option) => PASSWORD_CHARACTER_SETS[option]);

  if (selectedSets.length === 0) {
    throw new Error('Selecciona al menos un tipo de carácter');
  }
  if (!Number.isInteger(length) || length < selectedSets.length) {
    throw new Error('La longitud no permite incluir todos los tipos seleccionados');
  }

  const allCharacters = selectedSets.join('');
  const characters = selectedSets.map((characterSet) =>
    characterSet[secureRandomIndex(characterSet.length)],
  );

  while (characters.length < length) {
    characters.push(allCharacters[secureRandomIndex(allCharacters.length)]);
  }

  for (let index = characters.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1);
    [characters[index], characters[swapIndex]] = [characters[swapIndex], characters[index]];
  }

  return characters.join('');
}