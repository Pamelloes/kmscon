/*
 * kmscon - Text Renderer
 *
 * Copyright (c) 2012 David Herrmann <dh.herrmann@googlemail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * SECTION:text
 * @short_description: Text Renderer
 * @include: text.h
 *
 * TODO
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "shl_dlist.h"
#include "shl_log.h"
#include "shl_misc.h"
#include "shl_register.h"
#include "text.h"
#include <time.h>
#include "uterm_video.h"

#define LOG_SUBSYSTEM "text"

static struct shl_register text_reg = SHL_REGISTER_INIT(text_reg);

static inline void kmscon_text_destroy(void *data)
{
	const struct kmscon_text_ops *ops = data;

	kmscon_module_unref(ops->owner);
}

/**
 * kmscon_text_register:
 * @ops: Text operations and name for new backend
 *
 * This register a new text backend with operations set to @ops. The name
 * @ops->name must be valid.
 *
 * The first font that is registered automatically becomes the default and
 * fallback. So make sure you register a safe fallback as first backend.
 * If this is unregistered, the next in the list becomes the default
 * and fallback.
 *
 * Returns: 0 on success, negative error code on failure
 */
SHL_EXPORT
int kmscon_text_register(const struct kmscon_text_ops *ops)
{
	int ret;

	if (!ops)
		return -EINVAL;

	log_debug("register text backend %s", ops->name);

	ret = shl_register_add_cb(&text_reg, ops->name, (void*)ops,
				  kmscon_text_destroy);
	if (ret) {
		log_error("cannot register text backend %s: %d", ops->name,
			  ret);
		return ret;
	}

	kmscon_module_ref(ops->owner);
	return 0;
}

/**
 * kmscon_text_unregister:
 * @name: Name of backend
 *
 * This unregisters the text-backend that is registered with name @name. If
 * @name is not found, nothing is done.
 */
SHL_EXPORT
void kmscon_text_unregister(const char *name)
{
	log_debug("unregister backend %s", name);
	shl_register_remove(&text_reg, name);
}

static int new_text(struct kmscon_text *text, const char *backend,
		    struct conf_ctx *conf_ctx, struct kmscon_conf_t *conf)
{
	struct shl_register_record *record;
	const char *name = backend ? backend : "<default>";
	int ret;

	memset(text, 0, sizeof(*text));
	text->ref = 1;

	if (backend)
		record = shl_register_find(&text_reg, backend);
	else
		record = shl_register_first(&text_reg);

	if (!record) {
		log_error("requested backend '%s' not found", name);
		return -ENOENT;
	}

	text->record = record;
	text->ops = record->data;
	text->conf_ctx = conf_ctx;
	text->conf = conf;

	if (text->ops->init)
		ret = text->ops->init(text);
	else
		ret = 0;

	if (ret) {
		log_warning("backend %s cannot create renderer", name);
		shl_register_record_unref(record);
		return ret;
	}

	return 0;
}

/**
 * kmscon_text_new:
 * @out: A pointer to the new text-renderer is stored here
 * @backend: Backend to use or NULL for default backend
 * @conf_ctx: ??
 * @conf: The configuration struct
 *
 * Returns: 0 on success, error code on failure
 */
int kmscon_text_new(struct kmscon_text **out, const char *backend,
		    struct conf_ctx *conf_ctx, struct kmscon_conf_t *conf)
{
	struct kmscon_text *text;
	int ret;

	if (!out)
		return -EINVAL;

	text = malloc(sizeof(*text));
	if (!text) {
		log_error("cannot allocate memory for new text-renderer");
		return -ENOMEM;
	}

	ret = new_text(text, backend, conf_ctx, conf);
	if (ret) {
		if (backend)
			ret = new_text(text, NULL, conf_ctx, conf);
		if (ret)
			goto err_free;
	}

	log_debug("using: be: %s", text->ops->name);
	*out = text;
	return 0;

err_free:
	free(text);
	return ret;
}

/**
 * kmscon_text_ref:
 * @text: Valid text-renderer object
 *
 * This increases the reference count of @text by one.
 */
void kmscon_text_ref(struct kmscon_text *text)
{
	if (!text || !text->ref)
		return;

	++text->ref;
}

/**
 * kmscon_text_unref:
 * @text: Valid text-renderer object
 *
 * This decreases the reference count of @text by one. If it drops to zero, the
 * object is freed.
 */
void kmscon_text_unref(struct kmscon_text *text)
{
	if (!text || !text->ref || --text->ref)
		return;

	log_debug("freeing text renderer");
	kmscon_text_unset(text);

	if (text->ops->destroy)
		text->ops->destroy(text);
	shl_register_record_unref(text->record);
	free(text);
}

/**
 * kmscon_text_set:
 * @txt: Valid text-renderer object
 * @fonts: An array of the eight font objects
 * @disp: display object
 *
 * This makes the text-renderer @txt use the fonts @fonts and screen @screen. You
 * can drop your reference to both after calling this.
 * This calls kmscon_text_unset() first to remove all previous associations.
 * None of the arguments can be NULL!
 * The fonts are indexed by the 8 possible combinations of the attribute flags.
 * The first font (no attributes) must not be NULL. If any of the others are NULL
 * they will be set to the nearest alternative.
 * If this function fails then you must assume that no font/screen will be set
 * and the object is invalid.
 * The caller must make sure that all of the fonts have the same metrics. The renderers
 * will always use the metrics of the first @font.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int kmscon_text_set(struct kmscon_text *txt,
		    struct kmscon_font *fonts[8],
		    struct uterm_display *disp)
{
	int ret, i;

	if (!txt || !fonts || !fonts[0] || !disp)
		return -EINVAL;

	for (i = 0; i < 8; i++) {
		log_warning("KTS Font %d: %p", i, fonts[i]);
		if (fonts[i]) continue;

		// Due to the way the flags are set up, this should
		// propagate correctly
		if (i & KMSCON_TEXT_ITALIC)
			fonts[i] = fonts[i ^ KMSCON_TEXT_ITALIC];
		else if (i & KMSCON_TEXT_UNDERLINE)
			fonts[i] = fonts[i ^ KMSCON_TEXT_UNDERLINE];
		else if (i & KMSCON_TEXT_BOLD) 
			fonts[i] = fonts[i ^ KMSCON_TEXT_BOLD];

		// But make sure it works, anyways
		if (!fonts[i]) return -EINVAL;
	}

	kmscon_text_unset(txt);

	memcpy(txt->fonts, fonts, 8 * sizeof(struct kmscon_font*));
	txt->disp = disp;

	if (txt->ops->set) {
		ret = txt->ops->set(txt);
		if (ret) {
			log_warning("ops fail");
			memset(txt->fonts, 0, 8 * sizeof(struct kmscon_font*));
			return ret;
		}
	}

	for (i = 0; i < 8; i++)
		kmscon_font_ref(txt->fonts[i]);
	uterm_display_ref(txt->disp);

	return 0;
}

/**
 * kmscon_text_unset():
 * @txt: text renderer
 *
 * This redos kmscon_text_set() by dropping the internal references to the font
 * and screen and invalidating the object. You need to call kmscon_text_set()
 * again to make use of this text renderer.
 * This is automatically called when the text renderer is destroyed.
 */
void kmscon_text_unset(struct kmscon_text *txt)
{
	int i;

	if (!txt || !txt->disp || !txt->fonts[0])
		return;

	if (txt->ops->unset)
		txt->ops->unset(txt);

	for (i = 0; i < 8; i++)
		kmscon_font_unref(txt->fonts[i]);
	uterm_display_unref(txt->disp);

	memset(txt->fonts, 0, 8 * sizeof(struct kscon_font*));
	txt->disp = NULL;
	txt->cols = 0;
	txt->rows = 0;
	txt->rendering = false;
}

/**
 * kmscon_text_get_cols:
 * @txt: valid text renderer
 *
 * After setting the arguments with kmscon_text_set(), the renderer will compute
 * the number of columns/rows of the console that it can display on the screen.
 * You can retrieve these values via these functions.
 * If kmscon_text_set() hasn't been called, this will return 0.
 *
 * Returns: Number of columns or 0 if @txt is invalid
 */
unsigned int kmscon_text_get_cols(struct kmscon_text *txt)
{
	if (!txt)
		return 0;

	return txt->cols;
}

/**
 * kmscon_text_get_rows:
 * @txt: valid text renderer
 *
 * After setting the arguments with kmscon_text_set(), the renderer will compute
 * the number of columns/rows of the console that it can display on the screen.
 * You can retrieve these values via these functions.
 * If kmscon_text_set() hasn't been called, this will return 0.
 *
 * Returns: Number of rows or 0 if @txt is invalid
 */
unsigned int kmscon_text_get_rows(struct kmscon_text *txt)
{
	if (!txt)
		return 0;

	return txt->rows;
}

/**
 * kmscon_text_prepare:
 * @txt: valid text renderer
 *
 * This starts a rendering-round. When rendering a console via a text renderer,
 * you have to call this first, then render all your glyphs via
 * kmscon_text_draw() and finally use kmscon_text_render(). If you modify this
 * renderer during rendering or if you activate different OpenGL contexts in
 * between, you need to restart rendering by calling kmscon_text_prepare() again
 * and redoing everything from the beginning.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int kmscon_text_prepare(struct kmscon_text *txt)
{
	int ret = 0;

	int64_t off, msec;
	struct timespec spec;

	if (!txt || !txt->fonts[0] || !txt->disp)
		return -EINVAL;

	// Update the blink status
	if (txt->conf->cblink || txt->conf->tblink) {
		clock_gettime(CLOCK_MONOTONIC, &spec);
		off = spec.tv_sec;
		msec = spec.tv_nsec / 1e6;
		off = off * 1000 + msec;
		off /= 250;
		
		txt->blink = off % 2;
	}

	txt->rendering = true;
	if (txt->ops->prepare)
		ret = txt->ops->prepare(txt);
	if (ret)
		txt->rendering = false;

	return ret;
}

/**
 * kmscon_text_draw:
 * @txt: valid text renderer
 * @id: a unique ID that identifies @ch globally
 * @ch: ucs4 symbol you want to draw
 * @len: length of @ch or 0 for empty cell
 * @width: cell-width of character
 * @posx: X-position of the glyph
 * @posy: Y-position of the glyph
 * @attr: glyph attributes
 *
 * This draws a single glyph at the requested position. The position is a
 * console position, not a pixel position! You must precede this call with
 * kmscon_text_prepare(). Use this function to feed all glyphs into the
 * rendering pipeline and finally call kmscon_text_render().
 *
 * Returns: 0 on success or negative error code if this glyph couldn't be drawn.
 */
int kmscon_text_draw(struct kmscon_text *txt,
		     uint32_t id, const uint32_t *ch, size_t len,
		     unsigned int width,
		     unsigned int posx, unsigned int posy,
		     const struct tsm_screen_attr *attr)
{
	if (!txt || !txt->rendering)
		return -EINVAL;
	if (posx >= txt->cols || posy >= txt->rows || !attr)
		return -EINVAL;

	return txt->ops->draw(txt, id, ch, len, width, posx, posy, attr);
}

/**
 * kmscon_text_render:
 * @txt: valid text renderer
 *
 * This does the final rendering round after kmscon_text_prepare() has been
 * called and all glyphs were sent to the renderer via kmscon_text_draw().
 *
 * Returns: 0 on success, negative error on failure.
 */
int kmscon_text_render(struct kmscon_text *txt)
{
	int ret = 0;

	if (!txt || !txt->rendering)
		return -EINVAL;

	if (txt->ops->render)
		ret = txt->ops->render(txt);
	txt->rendering = false;

	return ret;
}

/**
 * kmscon_text_abort:
 * @txt: valid text renderer
 *
 * If you called kmscon_text_prepare() but you want to abort rendering instead
 * of finishing it with kmscon_text_render(), you can safely call this to reset
 * internal state. It is optional to call this or simply restart rendering.
 * Especially if the other renderers return an error, then they probably already
 * aborted rendering and it is not required to call this.
 */
void kmscon_text_abort(struct kmscon_text *txt)
{
	if (!txt || !txt->rendering)
		return;

	if (txt->ops->abort)
		txt->ops->abort(txt);
	txt->rendering = false;
}

int kmscon_text_draw_cb(struct tsm_screen *con,
			uint32_t id, const uint32_t *ch, size_t len,
			unsigned int width,
			unsigned int posx, unsigned int posy,
			const struct tsm_screen_attr *attr,
			tsm_age_t age, void *data)
{
	return kmscon_text_draw(data, id, ch, len, width, posx, posy, attr);
}
