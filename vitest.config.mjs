import { defineConfig, configDefaults } from 'vitest/config';

export default defineConfig({
  test: {
    // .claude/worktrees/* — рабочие копии репозитория, созданные агентскими
    // сессиями. Без этого исключения vitest находит в них второй server.test.mjs
    // и гоняет весь набор дважды: 392 теста вместо 196, а падение любого теста
    // отчитывается парой, будто дефектов вдвое больше.
    exclude: [...configDefaults.exclude, '**/.claude/worktrees/**'],
  },
});
