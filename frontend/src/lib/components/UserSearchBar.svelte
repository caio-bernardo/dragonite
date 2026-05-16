<script lang="ts">
  import { Search } from '@lucide/svelte';
  import { Navigation } from '@skeletonlabs/skeleton-svelte';
  import { matrixService } from '$lib';

  let { isRail = false, onExpand = () => {} }: { isRail: boolean; onExpand?: () => void } = $props();

  let query = $state('');
  let results = $state<{ userId: string; displayName: string; avatarUrl: string }[]>([]);
  let isLoading = $state(false);
  let debounceTimer: ReturnType<typeof setTimeout>;
  let inputContainer: HTMLDivElement = $state(null!);
  let dropdownStyle = $state('');

  function updateDropdownPosition() {
    if (inputContainer) {
      const rect = inputContainer.getBoundingClientRect();
      dropdownStyle = `top:${rect.bottom + 4}px; left:${rect.left}px; width:${rect.width}px;`;
    }
  }

  function handleInput() {
    updateDropdownPosition();
    clearTimeout(debounceTimer);
    if (query.trim().length < 2) { results = []; return; }
    debounceTimer = setTimeout(async () => {
      isLoading = true;
      try {
        results = await matrixService.searchUsers(query);
      } catch {
        results = [];
      } finally {
        isLoading = false;
      }
    }, 400);
  }

  function handleClickOutside(e: MouseEvent) {
    if (inputContainer && !inputContainer.contains(e.target as Node)) {
      results = [];
      query = '';
    }
  }
</script>

<svelte:window onclick={handleClickOutside} />
{#if isRail}
  <Navigation.Trigger onclick={onExpand}>
    <Search class="size-5" />
    <Navigation.TriggerText>Search</Navigation.TriggerText>
  </Navigation.Trigger>
{:else}
  <div class="relative mx-2" bind:this={inputContainer}>
    <div class="flex items-center gap-2 rounded-base bg-surface-100-900 px-3 py-2">
      <Search class="size-4 shrink-0 opacity-50" />
      <input
        type="search"
        class="w-full bg-transparent text-sm outline-none placeholder:opacity-50"
        placeholder="Buscar usuário..."
        bind:value={query}
        oninput={handleInput}
      />
      {#if isLoading}<span class="animate-spin opacity-50">⟳</span>{/if}
    </div>

    {#if results.length > 0}
      <ul class="card bg-surface-100-900 fixed z-[999] max-h-80 overflow-y-auto shadow-lg" style={dropdownStyle}>
        {#each results as user}
          <li class="hover:bg-surface-200-800 flex cursor-pointer items-center gap-3 px-3 py-2 transition-colors">
            <div class="bg-surface-300-700 flex size-8 shrink-0 items-center justify-center overflow-hidden rounded-full text-xs font-bold uppercase">
              {#if user.avatarUrl}
                <img src={user.avatarUrl} alt={user.displayName} class="size-full object-cover" />
              {:else}
                {user.displayName?.[0] ?? '?'}
              {/if}
            </div>
            <div class="min-w-0">
              <p class="truncate text-sm font-medium">{user.displayName}</p>
              <p class="truncate text-xs opacity-50">{user.userId}</p>
            </div>
          </li>
        {/each}
      </ul>
    {:else if query.length >= 2 && !isLoading}
      <div class="card bg-surface-100-900 fixed z-[999] px-3 py-2 text-sm" style={dropdownStyle}>
        <p class="opacity-50">Nenhum usuário encontrado</p>
      </div>
    {/if}
  </div>
{/if}