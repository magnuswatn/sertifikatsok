<script>
    import { createEventDispatcher } from "svelte";
    import MaterializeButton from "./MaterializeButton.svelte";

    const dispatch = createEventDispatcher();
</script>

<MaterializeButton
    data_position="top"
    data_tooltip="Vis PEM"
    on:click={() => dispatch("open")}
>
    <i class="material-icons">content_copy</i>
</MaterializeButton>
