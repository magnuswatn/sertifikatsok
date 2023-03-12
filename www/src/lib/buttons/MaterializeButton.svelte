<script>
    export let data_position;
    export let data_tooltip;

    import { onMount, onDestroy } from "svelte";

    onMount(() => {
        window.M.Tooltip.init(button, {});
    });
    onDestroy(() => {
        window.M.Tooltip.getInstance(button).destroy();
    });

    let button;
</script>

<button
    class="btn-floating btn-small waves-effect waves-light red tooltipped hoverable"
    data-position={data_position}
    data-tooltip={data_tooltip}
    bind:this={button}
    on:click
>
    <slot />
</button>
