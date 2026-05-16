<script lang="ts">
	import NavigationBarView from '$lib/components/NavigationBarView.svelte';
	import NavigationSideBarView from '$lib/components/NavigationSideBarView.svelte';

	let { children } = $props();
</script>

<div
    class="grid min-h-screen w-full grid-cols-[auto_1fr] items-stretch border border-surface-200-800 max-lg:grid-cols-1 max-lg:grid-rows-[1fr_auto]"
>
    <header
        class="max-lg:fixed max-lg:right-0 max-lg:bottom-0 max-lg:left-0 max-lg:order-2 max-lg:col-span-full"
    >
        <nav class="hidden h-full lg:block">
            <NavigationSideBarView></NavigationSideBarView>
        </nav>
        <nav class="h-full lg:hidden">
            <NavigationBarView></NavigationBarView>
        </nav>
    </header>

    <div class="max-lg:order-1 max-lg:col-span-full">
        {@render children()}
    </div>
</div>
