<script>
  import { resolve } from '$app/paths';
	import { HouseIcon, MessageSquare, Search, SettingsIcon } from '@lucide/svelte';
	import { Avatar, Navigation } from '@skeletonlabs/skeleton-svelte';
	import { matrixService } from '$lib';

	let searchOpen = $state(false);
	let query = $state('');
	let results = $state([]);
	let isLoading = $state(false);
	let debounceTimer;

	function toggleSearch() {
		searchOpen = !searchOpen;
		if (!searchOpen) { query = ''; results = []; }
	}

	function handleInput() {
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

	const links = [
		{ label: 'Home', href: '/dashboard', icon: HouseIcon },
		{ label: 'Rooms', href: '/dashboard/rooms', icon: MessageSquare },
		{ label: 'Settings', href: '/#', icon: SettingsIcon }
	];

	let avatarSrc = matrixService.userProfile.avatarUrl;
	let avatarFallback = matrixService.userProfile.displayname.charAt(0).toUpperCase() || 'J';
</script>

{#if searchOpen}
	<div class="fixed bottom-16 left-0 right-0 z-[100] bg-surface-100-900 p-3 shadow-lg">
		<div class="flex items-center gap-2 rounded-base bg-surface-200-800 px-3 py-2">
			<Search class="size-4 shrink-0 opacity-50" />
			<input
				autofocus
				type="search"
				class="w-full bg-transparent text-sm outline-none placeholder:opacity-50"
				placeholder="Buscar usuário..."
				bind:value={query}
				oninput={handleInput}
			/>
		</div>
		{#if results.length > 0}
			<ul class="mt-2 max-h-64 overflow-y-auto rounded-base">
				{#each results as user}
					<li class="hover:bg-surface-200-800 flex cursor-pointer items-center gap-3 px-3 py-2">
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
			<p class="mt-2 px-3 py-2 text-sm opacity-50">Nenhum usuário encontrado</p>
		{/if}
	</div>
{/if}

<Navigation layout="bar">
	<Navigation.Menu class="grid grid-cols-4 gap-2">
		<Navigation.Trigger onclick={toggleSearch}>
			<Search class="size-5" />
			<Navigation.TriggerText>Search</Navigation.TriggerText>
		</Navigation.Trigger>
		{#each links as link (link)}
			{@const Icon = link.icon}
			<Navigation.TriggerAnchor href={link.href}>
				<Icon class="size-5" />
				<Navigation.TriggerText>{link.label}</Navigation.TriggerText>
			</Navigation.TriggerAnchor>
		{/each}
		<Navigation.TriggerAnchor
			href={resolve('/dashboard/profile')}
			title="Your Profile"
			aria-label="Your Profile"
		>
			<Avatar class="size-10">
				<Avatar.Image src={avatarSrc} alt="user's profile picture" />
				<Avatar.Fallback>{avatarFallback}</Avatar.Fallback>
			</Avatar>
			<Navigation.TriggerText>You</Navigation.TriggerText>
		</Navigation.TriggerAnchor>
	</Navigation.Menu>
</Navigation>
