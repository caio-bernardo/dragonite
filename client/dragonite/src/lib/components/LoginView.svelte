<script lang="ts">
</script>

<form method="POST" class="mx-auto w-full max-w-sm space-y-4 rounded-xl border-2 p-6">
	<fieldset class="space-y-4">
		<legend class="text-2xl font-bold">Sign In</legend>

		<label class="label">
			<span class="label-text">Host Server</span>
			<input name="host" type="text" class="input" placeholder="matrix.org" value="matrix.org" />
		</label>

		<label class="label">
			<span class="label-text">Email</span>
			<input name="email" type="email" class="input" placeholder="user@email.com" />
		</label>

		<label class="label">
			<span class="label-text">Password</span>
			<input name="password" class="input" type="password" placeholder="Password" />
		</label>
	</fieldset>
	<fieldset class="flex justify-end">
		<button type="submit" class="btn preset-filled-primary-500">Log in</button>
	</fieldset>
</form>

<style>
	legend {
		margin-left: calc(50% - 35px - 8px);
	}
</style>
