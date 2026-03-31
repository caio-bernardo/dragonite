<script lang="ts">
	import LoginView from '$lib/components/LoginView.svelte';

	const currentYear = new Date().getFullYear();
</script>

<main class="grid h-screen min-h-screen grid-rows-[auto_1fr_auto] items-center">
	<hgroup class="p-4 text-center">
		<h1 class="h1">Dragonite</h1>
		<p class="text-muted-foreground text-xl">
			Definetily a <span class="italic">&lt;Matrix.org&gt;</span> Client!
		</p>
	</hgroup>

	<div>
		<LoginView />
		<p class="text-center">
			Don't have an Account? <a class="anchor" href="#top">Create one here</a>.
		</p>
	</div>

	<footer class="flex items-center justify-center p-4">
		<a class="anchor" href="https://github.com/caio-bernardo/dragonite"> Source Code </a>
		<span class="mx-2">|</span>
		<p>Dragonite &copy; {currentYear}</p>
	</footer>
</main>
