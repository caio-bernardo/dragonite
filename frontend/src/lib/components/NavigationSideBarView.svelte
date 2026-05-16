<script>
	import { resolve } from '$app/paths';
	import { matrixService } from '$lib/stores/matrix.svelte';
	import { ArrowLeftRightIcon, HouseIcon, MessageSquare, SettingsIcon } from '@lucide/svelte';
	import { Avatar, Navigation } from '@skeletonlabs/skeleton-svelte';
  import UserSearchBar from '$lib/components/UserSearchBar.svelte';

	let isLayoutRail = $state(true);

	function toggleLayout() {
		isLayoutRail = !isLayoutRail;
	}

	const links = [
		{ label: 'Home', href: '/dashboard', icon: HouseIcon },
		{ label: 'Rooms', href: '/dashboard/rooms', icon: MessageSquare },
		{ label: 'Settings', href: '/#', icon: SettingsIcon }
	];

	let avatarSrc = matrixService.userProfile.avatarUrl;
	let avatarFallback = matrixService.userProfile.displayname.charAt(0).toUpperCase() || 'J';
</script>

<Navigation layout={isLayoutRail ? 'rail' : 'sidebar'} class="grid grid-rows-[auto_1fr_auto] gap-4">
	<Navigation.Header>
		<Navigation.Trigger onclick={toggleLayout}>
			<ArrowLeftRightIcon class={isLayoutRail ? 'size-5' : 'size-4'} />
			{#if !isLayoutRail}<span>Resize</span>{/if}
		</Navigation.Trigger>
	</Navigation.Header>
	<Navigation.Content class="overflow-visible">
		<Navigation.Menu>
			<UserSearchBar isRail={isLayoutRail} onExpand={() => (isLayoutRail = false)} />
			{#each links as link (link)}
				{@const Icon = link.icon}
				<Navigation.TriggerAnchor href={link.href}>
					<Icon class={isLayoutRail ? 'size-5' : 'size-4'} />
					<Navigation.TriggerText>{link.label}</Navigation.TriggerText>
				</Navigation.TriggerAnchor>
			{/each}
		</Navigation.Menu>
	</Navigation.Content>
	<Navigation.Footer>
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
	</Navigation.Footer>
</Navigation>
