import { useForm } from "react-hook-form";
import { z } from "zod";
import { create } from "zustand";

export const compatibilitySchema = z.object({
  name: z.string().min(1),
});

export type CompatibilityInput = z.infer<typeof compatibilitySchema>;

export function useCompatibilityForm() {
  return useForm<CompatibilityInput>();
}

interface LocalFixtureState {
  readonly expanded: boolean;
  toggle(): void;
}

export const useLocalFixture = create<LocalFixtureState>((set) => ({
  expanded: false,
  toggle: () => set((state) => ({ expanded: !state.expanded })),
}));
