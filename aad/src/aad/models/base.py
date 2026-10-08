"""Shared compilation and I/O for the three baseline NIDS models."""

from __future__ import annotations

import logging

import tensorflow as tf
from tensorflow import keras

log = logging.getLogger(__name__)


def _portable_keras_weights() -> None:
    """Make .keras files load on both Windows and Linux (WSL GPU runs).

    Keras 2.13 names the HDF5 weight groups with ``tf.io.gfile.join``, so a file
    saved on Windows holds ``_layer_checkpoint_dependencies\\dense`` and Linux
    cannot find it (and the reverse). Write with "/" from now on and accept
    either separator on load, so existing Windows-saved models keep working.
    """
    from keras.src.saving import saving_lib

    store = saving_lib.H5IOStore
    if getattr(store, "_aad_portable", False):
        return
    make, get = store.make, store.get

    def portable_make(self, path):
        return make(self, path.replace("\\", "/") if path else path)

    def portable_get(self, path):
        if not path:
            return get(self, path)
        for p in (path, path.replace("\\", "/"), path.replace("/", "\\")):
            found = get(self, p)
            if len(found):
                return found
        return found

    store.make, store.get, store._aad_portable = portable_make, portable_get, True


_portable_keras_weights()

# Every model in this project agrees on these two facts.
N_CLASSES = 2
OUTPUT_ACTIVATION = "softmax"


def set_seeds(seed: int) -> None:
    """Seed python, numpy and tensorflow in one call."""
    keras.utils.set_random_seed(seed)


def compile_model(model: keras.Model, optimizer: str, learning_rate: float) -> keras.Model:
    """CategoricalCrossentropy over a 2-unit softmax.

    ART's TensorFlowV2Classifier is handed this same loss object in phase 3, so
    the attack gradients match the training gradients exactly.
    """
    if optimizer.lower() != "adam":
        raise ValueError(f"unsupported optimizer {optimizer!r}")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss=keras.losses.CategoricalCrossentropy(),
        metrics=[
            keras.metrics.CategoricalAccuracy(name="accuracy"),
            keras.metrics.Precision(class_id=1, name="precision"),
            keras.metrics.Recall(class_id=1, name="recall"),
        ],
    )
    return model


def build_callbacks(cfg: dict) -> list[keras.callbacks.Callback]:
    es = cfg["early_stopping"]
    rl = cfg["reduce_lr"]
    return [
        keras.callbacks.EarlyStopping(
            monitor=es["monitor"],
            patience=int(es["patience"]),
            restore_best_weights=bool(es["restore_best_weights"]),
            verbose=1,
        ),
        keras.callbacks.ReduceLROnPlateau(
            monitor=rl["monitor"],
            factor=float(rl["factor"]),
            patience=int(rl["patience"]),
            min_lr=float(rl["min_lr"]),
            verbose=1,
        ),
    ]


def summarise(model: keras.Model) -> str:
    lines: list[str] = []
    model.summary(print_fn=lines.append, line_length=88)
    return "\n".join(lines)
