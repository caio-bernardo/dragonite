<script lang="ts">
	import { matrixService } from '$lib';
	import { Avatar } from '@skeletonlabs/skeleton-svelte';

	let localpart = $state(matrixService.getUserID() || '@joao');
	let displayName = $state(matrixService.userProfile.displayname || 'João Silva');
	let avatarUrl = $state(matrixService.userProfile.avatarUrl || 'https://i.pravatar.cc/80?img=48');

	let isEditing = $state(false);
	let editDisplayName = $derived(displayName);
	let editAvatarFile = $state<File | null>(null);
	let editAvatarPreview = $derived(avatarUrl);
	let isSaving = $state(false);
	let saveMessage = $state('');

	function handleAvatarChange(event: Event) {
		const target = event.target as HTMLInputElement;
		const file = target.files?.[0];

		if (file && file.type.startsWith('image/')) {
			editAvatarFile = file;

			// Create preview
			const reader = new FileReader();
			reader.onload = (e) => {
				editAvatarPreview = e.target?.result as string;
			};
			reader.readAsDataURL(file);
		} else {
			saveMessage = 'Please select a valid image file.';
			setTimeout(() => (saveMessage = ''), 3000);
		}
	}

	async function handleSave(event: Event) {
		event.preventDefault();
		isSaving = true;
		saveMessage = '';
		try {
			// Update display name
			if (editDisplayName !== displayName) {
				await matrixService.updateProfile({ displayname: editDisplayName });
			}

			// Upload and update avatar
			if (editAvatarFile) {
				await matrixService.uploadAvatar(editAvatarFile);
			}

			displayName = editDisplayName;
			avatarUrl = editAvatarPreview;
			isEditing = false;
			editAvatarFile = null;
			saveMessage = 'Profile updated successfully!';
			setTimeout(() => (saveMessage = ''), 3000);
		} catch (error) {
			console.error('Error updating profile:', error);
			saveMessage = 'Error updating profile. Please try again.';
			setTimeout(() => (saveMessage = ''), 3000);
		} finally {
			isSaving = false;
		}
	}

	function handleCancel() {
		editDisplayName = displayName;
		editAvatarFile = null;
		editAvatarPreview = avatarUrl;
		isEditing = false;
		saveMessage = '';
	}
</script>

<main class="h-screen bg-surface-900 p-8">
	<div class="mx-auto max-w-md">
		<!-- Profile Header -->
		<div class="mb-8 text-center">
			<h1 class="mb-6 text-3xl font-bold text-primary-300">Profile</h1>

			{#if !isEditing}
				<!-- View Mode -->
				<div class="mb-6">
					<Avatar class="mx-auto size-32">
						<Avatar.Image src={avatarUrl} alt="Profile" />
						<Avatar.Fallback>User</Avatar.Fallback>
					</Avatar>
				</div>

				<div class="mb-6 space-y-3">
					<div>
						<p class="mb-1 text-sm text-primary-400">User ID</p>
						<p class="text-lg font-semibold text-primary-300">{localpart}</p>
					</div>
					<div>
						<p class="mb-1 text-sm text-primary-400">Display Name</p>
						<p class="text-lg font-semibold text-primary-50">{displayName}</p>
					</div>
				</div>

				<button
					onclick={() => (isEditing = true)}
					class="w-full rounded-lg bg-primary-500 px-4 py-2 font-semibold text-white transition hover:bg-primary-600"
				>
					Edit Profile
				</button>
			{:else}
				<!-- Edit Mode -->
				<form onsubmit={handleSave} class="space-y-4 rounded-lg bg-surface-800 p-6">
					<div>
						<label for="avatar" class="mb-2 block text-sm font-medium text-primary-400">
							Profile Picture
						</label>
						<div class="flex flex-col items-center gap-4">
							<Avatar class="size-24">
								<Avatar.Image src={editAvatarPreview} alt="Preview" />
								<Avatar.Fallback>User</Avatar.Fallback>
							</Avatar>
							<label
								for="avatar"
								class="cursor-pointer rounded-lg border border-primary-500 bg-surface-700 px-4 py-2 font-medium text-primary-50 transition hover:bg-surface-600"
							>
								Choose Image
							</label>
							<input
								id="avatar"
								type="file"
								accept="image/*"
								class="hidden"
								onchange={handleAvatarChange}
							/>
							{#if editAvatarFile}
								<p class="text-sm text-primary-300">Selected: {editAvatarFile.name}</p>
							{/if}
						</div>
					</div>

					<div>
						<label for="displayName" class="mb-2 block text-sm font-medium text-primary-400">
							Display Name
						</label>
						<input
							id="displayName"
							type="text"
							bind:value={editDisplayName}
							class="w-full rounded-lg border border-primary-500 bg-surface-700 px-3 py-2 text-primary-50 placeholder-primary-600 focus:ring-2 focus:ring-primary-400 focus:outline-none"
							placeholder="Your display name"
							required
						/>
					</div>

					<div class="flex gap-3 pt-4">
						<button
							type="submit"
							disabled={isSaving || (!editAvatarFile && editDisplayName === displayName)}
							class="flex-1 rounded-lg bg-primary-500 px-4 py-2 font-semibold text-white transition hover:bg-primary-600 disabled:bg-primary-600 disabled:opacity-50"
						>
							{isSaving ? 'Saving...' : 'Save'}
						</button>
						<button
							type="button"
							onclick={handleCancel}
							disabled={isSaving}
							class="flex-1 rounded-lg bg-surface-700 px-4 py-2 font-semibold text-primary-50 transition hover:bg-surface-600 disabled:opacity-50"
						>
							Cancel
						</button>
					</div>
				</form>
			{/if}

			{#if saveMessage}
				<div
					class="mt-4 rounded-lg p-3 text-center"
					class:bg-success-900={saveMessage.includes('successfully')}
					class:text-success-300={saveMessage.includes('successfully')}
					class:bg-error-900={saveMessage.includes('Error')}
					class:text-error-300={saveMessage.includes('Error')}
				>
					{saveMessage}
				</div>
			{/if}
		</div>
	</div>
</main>
